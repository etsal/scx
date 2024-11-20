#pragma once

#include "sdt_task.h"

#define SDT_TASK_FN_ATTRS	inline __attribute__((unused, always_inline))

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 15); /* number of pages */
        __ulong(map_extra, (1ull << 44)); /* start of mmap() region */
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

/* find the first empty slot */
static SDT_TASK_FN_ATTRS __s64 sdt_task_find_empty(struct sdt_task_desc __arena *desc)
{
	__u64 i;

	cast_kern(desc);

	for (i = 0; i < SDT_TASK_ENTS_PER_CHUNK; i++) {
		if (!desc->allocated[i])
			return i;
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

	new_page = bpf_arena_alloc_pages(&arena, NULL, 64, NUMA_NO_NODE, 0);
	if (!new_page)
		return NULL;

	/*
	 * Push all allocated elements except for last one that we use to
	 * satisfy the allocation.
	 */

	numelems = (64 * PAGE_SIZE) / pool->elem_size;
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
		desc->allocated[i] = false;
	}

	desc->nr_free = 0;
	desc->chunk = NULL;
	sdt_task_free_to_pool(desc, &sdt_task_desc_pool);
}

/* initialize the whole thing, maybe misnomer */
static SDT_TASK_FN_ATTRS int sdt_task_init(__u64 data_size)
{
	sdt_task_data_size = data_size;
	int ret;

	data_size = div_round_up(data_size, 8) * 8;
	data_size += sizeof(struct sdt_task_data);

	if (data_size > PAGE_SIZE)
		return -E2BIG;

	sdt_task_data_pool.elem_size = data_size;

	ret = sdt_alloc_chunk();
	if (ret < 0)
		return ret;

	return 0;
}

static SDT_TASK_FN_ATTRS void sdt_set_idx_state(struct sdt_task_desc *desc, int idx, bool state)
{
	bool __arena *allocated = (bool *)desc->allocated;

	cast_kern(allocated);

	allocated[idx] = state;
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

	chunk = desc->chunk;
	cast_kern(chunk);

	data = (struct sdt_task_data *)chunk->data;
	if (!data)
		goto done;

	desc->nr_free++;

	cast_kern(data);

	*data = (struct sdt_task_data) {
		.tid.gen = data->tid.gen + 1,
		.tptr = 0,
	};

	bpf_for(i, 0, sdt_task_data_size / 8) {
		data->data[i] = 0;
	}

done:
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

	/*
	 * Do the third level. As the full bit is not set, we know there must be
	 * at least one slot available and we can claim that slot and populate
	 * it if necessary. No need to back out and retry.
	 */
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
		if (!data)
			sdt_task_free_idx(pos);
		bpf_spin_lock(&sdt_task_lock);
		if (!data)
			goto out_unlock;

		cast_kern(data);

		data->tid.idx = pos;
		chunk->data[pos] = data;
	}

	/* init and return */
	cast_kern(data);
	data->tptr = (__u64)p;

	mval->tid = data->tid;
	mval->data = data;

out_unlock:
	bpf_spin_unlock(&sdt_task_lock);

	return data;
}
