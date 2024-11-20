#pragma once

#include "sdt_task.h"

#define SDT_TASK_FN_ATTRS	inline __attribute__((unused, always_inline))

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 15); /* number of pages */
#ifdef __TARGET_ARCH_arm64
        __ulong(map_extra, (1ull << 32)); /* start of mmap() region */
#else
        __ulong(map_extra, (1ull << 44)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");

/*
 * task BPF map entry recording the task's assigned ID and pointing to the data
 * area allocated in arena.
 */
struct sdt_task_map_val {
	union sdt_task_id		tid;
	struct sdt_task_data __arena	*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sdt_task_map_val);
} sdt_task_map SEC(".maps");

/*
 * XXX Hack to get the verifier to find the arena for sdt_exit_task.
 * As of 6.12-rc5, The verifier associates arenas with programs by
 * checking LD.IMM instruction operands for an arena and populating
 * the program state with the first instance it finds. This requires
 * accessing our global arena variable, but scx methods do not necessarily
 * do so while still using pointers from that arena. Insert a bpf_printk
 * statement that triggers at most once to generate an LD.IMM instruction
 * to access the arena and help the verifier.
 */
static bool sdt_verify_once;

static SDT_TASK_FN_ATTRS void sdt_arena_verify(void)
{

	if (sdt_verify_once)
		return;

	bpf_printk("Kernel pointer to arena is %p\n", &arena);
	sdt_verify_once = true;
}

struct sdt_task_desc __arena *sdt_task_desc_root;
static struct sdt_task_desc __arena *sdt_task_new_chunk; /* new chunk cache */
static __u64 __arena sdt_task_data_size; /* requested per-task data size */

private(LOCK) struct bpf_spin_lock sdt_task_lock;
private(POOL_LOCK) struct bpf_spin_lock sdt_task_pool_alloc_lock;

/* allocation pools */
struct sdt_task_pool __arena sdt_task_desc_pool = {
	.elem_size			= sizeof(struct sdt_task_desc),
};

struct sdt_task_pool __arena sdt_task_chunk_pool = {
	.elem_size			= sizeof(struct sdt_task_chunk),
};

struct sdt_task_pool __arena sdt_task_data_pool;

static SDT_TASK_FN_ATTRS int sdt_ffs(__u64 word)
{
	unsigned int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}

	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}

	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}

	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}

	if ((word & 0x1) == 0) {
		num += 1;
		word >>= 1;
	}

	return num;
}

/* find the first empty slot */
static SDT_TASK_FN_ATTRS __s64 sdt_task_find_empty(struct sdt_task_desc __arena *desc)
{
	__u64 i;

	cast_kern(desc);

	for (i = 0; i < SDT_TASK_CHUNK_BITMAP_U64S; i++) {
		if (desc->allocated[i] == ~0ULL)
			continue;

		return (i * 64) + sdt_ffs(~desc->allocated[i]);
	}

	return -EBUSY;
}

/* simple memory allocator */
static SDT_TASK_FN_ATTRS
void __arena *sdt_task_alloc_from_pool(struct sdt_task_pool __arena *pool)
{
	arena_list_node_t *elem = NULL;
	void __arena *new_page = NULL;
	arena_list_node_t *new_elem;
	__u32 u, numelems;

	/* if pool is empty, get new page */
	bpf_spin_lock(&sdt_task_pool_alloc_lock);

	if (pool->head.first) {
		elem = list_pop(&pool->head);
		bpf_spin_unlock(&sdt_task_pool_alloc_lock);
		return (void __arena *)elem;
	}

	bpf_spin_unlock(&sdt_task_pool_alloc_lock);

	new_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!new_page)
		return NULL;

	/*
	 * Push all allocated elements except for last one that we use to
	 * satisfy the allocation.
	 */

	numelems = PAGE_SIZE / pool->elem_size;

	bpf_for(u, 0, numelems - 1) {
		new_elem = new_page + u * pool->elem_size;

		bpf_spin_lock(&sdt_task_pool_alloc_lock);
		list_add_head(new_elem, &pool->head);
		bpf_spin_unlock(&sdt_task_pool_alloc_lock);
	}

	elem = new_page + (numelems - 1) * pool->elem_size;

	return (void __arena *)elem;
}

static SDT_TASK_FN_ATTRS
void sdt_task_free_to_pool(void __arena *ptr, struct sdt_task_pool __arena *pool)
{
	bpf_spin_lock(&sdt_task_pool_alloc_lock);
	list_pop(&pool->head);
	bpf_spin_unlock(&sdt_task_pool_alloc_lock);
}

/* alloc desc and chunk and link chunk to desc and return desc */
static SDT_TASK_FN_ATTRS int __arena sdt_alloc_chunk(void)
{
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_desc __arena *desc;

	chunk = sdt_task_alloc_from_pool(&sdt_task_chunk_pool);
	if (!chunk)
		return -ENOMEM;

	desc = sdt_task_alloc_from_pool(&sdt_task_desc_pool);
	if (!desc) {
		sdt_task_free_to_pool(chunk, &sdt_task_chunk_pool);
		return -ENOMEM;
	}

	sdt_task_desc_root = desc;

	cast_kern(desc);

	desc->nr_free = SDT_TASK_ENTS_PER_CHUNK;
	desc->chunk = chunk;

	return 0;
}

static SDT_TASK_FN_ATTRS void sdt_task_free_chunk(struct sdt_task_desc __arena *desc)
{
	struct sdt_task_chunk __arena *chunk;
	int i;

	cast_kern(desc);

	chunk = desc->chunk;
	cast_kern(chunk);

	/* Manually zero out the struct because memset() doesn't get inlined. */
	bpf_for(i, 0, SDT_TASK_ENTS_PER_CHUNK) {
		chunk->descs[i] = NULL;
	}
	sdt_task_free_to_pool(desc->chunk, &sdt_task_chunk_pool);

	bpf_for(i, 0, SDT_TASK_ENTS_PER_CHUNK) {
		desc->allocated[i] = (__u64)0;
	}

	desc->nr_free = 0;
	desc->chunk = NULL;
	sdt_task_free_to_pool(desc, &sdt_task_desc_pool);
}

/* initialize the whole thing, maybe misnomer */
static SDT_TASK_FN_ATTRS int sdt_task_init(__u64 data_size)
{
	int ret;

	sdt_task_data_size = data_size;

	data_size += data_size + sizeof(struct sdt_task_data);

	if (data_size > PAGE_SIZE)
		return -E2BIG;

	sdt_task_data_pool.elem_size = data_size;

	ret = sdt_alloc_chunk();
	if (ret < 0)
		return ret;

	return 0;
}

static SDT_TASK_FN_ATTRS void sdt_set_idx_state(struct sdt_task_desc *desc, __u64 pos, bool state)
{
	__u64 __arena *allocated = (__u64 *)desc->allocated;
	__u64 mask;

	cast_kern(allocated);

	mask = (__u64)1 << (pos % 64);

	if (state)
		allocated[pos / 64] |= mask;
	else
		allocated[pos / 64] &= ~mask;
}

static SDT_TASK_FN_ATTRS void sdt_task_free_idx(int idx)
{
	struct sdt_task_desc __arena *desc;
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_data __arena *data;
	int i;

	bpf_spin_lock(&sdt_task_lock);

	desc = sdt_task_desc_root;
	if (!desc) {
		bpf_spin_unlock(&sdt_task_lock);
		return;
	}

	cast_kern(desc);

	sdt_set_idx_state(desc, idx, false);
	desc->nr_free++;

	chunk = desc->chunk;
	cast_kern(chunk);

	data = (struct sdt_task_data *)chunk->data;
	if (!data) {
		bpf_spin_unlock(&sdt_task_lock);
		bpf_printk("%s: Freeing idx without data\n", __func__);
		return;
	}

	cast_kern(data);

	*data = (struct sdt_task_data) {
		.tid.gen = data->tid.gen + 1,
		.tptr = 0,
	};

	/* Zero out one word at a time. */
	bpf_for(i, 0, sdt_task_data_size / 8) {
		data->data[i] = 0;
	}

	bpf_spin_unlock(&sdt_task_lock);
	return;
}

static SDT_TASK_FN_ATTRS void sdt_task_free(struct task_struct *p)
{
	struct sdt_task_map_val *mval;

	sdt_arena_verify();

	mval = bpf_task_storage_get(&sdt_task_map, p, 0, 0);
	if (!mval)
		return;

	sdt_task_free_idx(mval->tid.idx);
	mval->data = NULL;
}

static SDT_TASK_FN_ATTRS struct sdt_task_data __arena *sdt_task_alloc(struct task_struct *p)
{
	struct sdt_task_data __arena *data = NULL;
	struct sdt_task_desc __arena *desc;
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_map_val *mval;
	__u64 pos;

	mval = bpf_task_storage_get(&sdt_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval)
		return NULL;

	bpf_spin_lock(&sdt_task_lock);

	desc = sdt_task_desc_root;

	pos = sdt_task_find_empty(desc);
	if (pos < 0)
		goto out_unlock;

	sdt_set_idx_state(desc, pos, true);

	cast_kern(desc);

	chunk = desc->chunk;
	cast_kern(chunk);

	/* populate leaf node if necessary */
	data = chunk->data[pos];
	if (!data) {
		bpf_spin_unlock(&sdt_task_lock);

		data = sdt_task_alloc_from_pool(&sdt_task_data_pool);
		if (!data) {
			sdt_task_free_idx(pos);
			return NULL;
		}

		bpf_spin_lock(&sdt_task_lock);
		chunk->data[pos] = data;
	}

	/* init and return */
	cast_kern(data);
	data->tid.idx = pos;
	data->tptr = (__u64)p;

	mval->tid = data->tid;
	mval->data = data;

out_unlock:
	bpf_spin_unlock(&sdt_task_lock);

	return data;
}
