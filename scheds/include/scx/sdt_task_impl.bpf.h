/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once

#include "sdt_task.h"

#define SDT_TASK_FN_ATTRS	inline __attribute__((unused, always_inline))

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 20); /* number of pages */
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

	bpf_printk("%s: arena pointer %p", __func__, &arena);
	sdt_verify_once = true;
}


static struct sdt_task_desc __arena *sdt_task_desc_root; /* radix tree root */
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
static SDT_TASK_FN_ATTRS __u64 sdt_chunk_find_empty(struct sdt_task_desc __arena *desc)
{
	__u64 freelist;
	__u64 i;

	cast_kern(desc);

	for (i = 0; i < SDT_TASK_CHUNK_BITMAP_U64S; i++) {
		freelist = ~desc->allocated[i];
		if (freelist == (__u64)0)
			continue;

		return (i * 64) + sdt_ffs(freelist);
	}

	return SDT_TASK_ENTS_PER_CHUNK;
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
		bpf_spin_unlock(&sdt_task_pool_alloc_lock);
		elem = list_pop(&pool->head);
		return (void __arena *)&elem->data;
	}

	bpf_spin_unlock(&sdt_task_pool_alloc_lock);

	new_page = bpf_arena_alloc_pages(&arena, NULL, SDT_TASK_ENT_PAGES, NUMA_NO_NODE, 0);
	if (!new_page)
		return NULL;

	/*
	 * Push all allocated elements except for last one that we use to
	 * satisfy the allocation.
	 */

	numelems = (SDT_TASK_ENT_PAGES * PAGE_SIZE) / pool->elem_size;

	bpf_for(u, 0, numelems - 1) {
		new_elem = new_page + u * pool->elem_size;

		bpf_spin_lock(&sdt_task_pool_alloc_lock);
		list_add_head(new_elem, &pool->head);
		bpf_spin_unlock(&sdt_task_pool_alloc_lock);
	}

	elem = new_page + (numelems - 1) * pool->elem_size;

	return (void __arena *)&elem->data;
}

static SDT_TASK_FN_ATTRS
void sdt_task_free_to_pool(void __arena *ptr, struct sdt_task_pool __arena *pool)
{
	arena_list_node_t *elem;
	__u64 __arena *data;
	int i;

	elem = arena_container_of(ptr, struct arena_list_node, data);

	/* Zero out one word at a time since we cannot use memset. */
	data = (__u64 __arena *)&elem->data;
	cast_kern(data);

	bpf_for(i, 0, pool->elem_size / 8) {
		data[i] = (__u64)0;
	}

	bpf_spin_lock(&sdt_task_pool_alloc_lock);
	list_add_head(elem, &pool->head);
	bpf_spin_unlock(&sdt_task_pool_alloc_lock);
}

/* alloc desc and chunk and link chunk to desc and return desc */
static SDT_TASK_FN_ATTRS struct sdt_task_desc __arena *sdt_alloc_chunk(void)
{
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_desc __arena *desc;
	struct sdt_task_desc __arena *out;

	chunk = sdt_task_alloc_from_pool(&sdt_task_chunk_pool);
	if (!chunk) {
		bpf_printk("%s: failed to allocated chunk", __func__);
		return NULL;
	}

	desc = sdt_task_alloc_from_pool(&sdt_task_desc_pool);
	if (!desc) {
		sdt_task_free_to_pool(chunk, &sdt_task_chunk_pool);
		bpf_printk("%s: failed to allocated desc", __func__);
		return NULL;
	}

	out = desc;

	cast_kern(desc);

	desc->nr_free = SDT_TASK_ENTS_PER_CHUNK;
	desc->chunk = chunk;

	return out;
}

static SDT_TASK_FN_ATTRS int sdt_pool_set_size(struct sdt_task_pool __arena *pool, __u64 data_size)
{
	/* All allocations are wrapped in a linked list node. */
	data_size += sizeof(struct arena_list_node);

	if (data_size > (SDT_TASK_ENT_PAGES * PAGE_SIZE)) {
		bpf_printk("allocation size %ld too large", data_size);
		return -E2BIG;
	}

	cast_kern(pool);
	pool->elem_size = data_size;

	return 0;
}

/* initialize the whole thing, maybe misnomer */
static SDT_TASK_FN_ATTRS int sdt_task_init(__u64 data_size)
{
	int ret;

	sdt_task_data_size = data_size;

	ret = sdt_pool_set_size(&sdt_task_chunk_pool, sizeof(struct sdt_task_chunk));
	if (ret != 0)
		return ret;

	ret = sdt_pool_set_size(&sdt_task_desc_pool, sizeof(struct sdt_task_desc));
	if (ret != 0)
		return ret;

	/* Page align and wrap data into a descriptor. */
	data_size += sizeof(struct sdt_task_data);
	data_size = div_round_up(data_size, 8) * 8;

	ret = sdt_pool_set_size(&sdt_task_data_pool, data_size);
	if (ret != 0)
		return ret;

	sdt_task_desc_root = sdt_alloc_chunk();
	if (sdt_task_desc_root == NULL)
		return -ENOMEM;

	return 0;
}

static SDT_TASK_FN_ATTRS
int sdt_set_idx_state(struct sdt_task_desc __arena *desc, __u64 pos, bool state)
{
	__u64 __arena *allocated = desc->allocated;
	__u64 bit;

	cast_kern(allocated);

	if (pos >= SDT_TASK_ENTS_PER_CHUNK) {
		bpf_spin_unlock(&sdt_task_lock);
		bpf_printk("invalid access (0x%d, %s)\n", pos, state ? "set" : "unset");

		bpf_spin_lock(&sdt_task_lock);
		return -EINVAL;
	}

	bit = (__u64)1 << (pos % 64);

	if (state)
		allocated[pos / 64] |= bit;
	else
		allocated[pos / 64] &= ~bit;

	return 0;
}

static SDT_TASK_FN_ATTRS void sdt_task_free_idx(__u64 idx)
{
	const __u64 mask = (1 << SDT_TASK_ENTS_PER_CHUNK_SHIFT) - 1;
	struct sdt_task_desc __arena *lv_desc[SDT_TASK_LEVELS];
	struct sdt_task_desc * __arena *desc_children;
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_desc __arena *desc;
	struct sdt_task_data __arena *data;
	__u64 u, level, shift, pos;
	__u64 lv_pos[SDT_TASK_LEVELS];
	int i;

	bpf_spin_lock(&sdt_task_lock);

	desc = sdt_task_desc_root;
	if (!desc) {
		bpf_spin_unlock(&sdt_task_lock);
		bpf_printk("%s: root not allocated", __func__);
		return;
	}

	bpf_for(level, 0, SDT_TASK_LEVELS) {
		shift = (SDT_TASK_LEVELS - 1 - level) * SDT_TASK_ENTS_PER_CHUNK_SHIFT;
		pos = (idx >> shift) & mask;

		lv_desc[level] = desc;
		lv_pos[level] = pos;

		if (level == SDT_TASK_LEVELS - 1)
			break;

		cast_kern(desc);

		chunk = desc->chunk;
		cast_kern(chunk);

		desc_children = (struct sdt_task_desc * __arena *)chunk->descs;
		desc = desc_children[pos];

		if (!desc) {
			bpf_spin_unlock(&sdt_task_lock);
			bpf_printk("freeing nonexistent idx [0x%lx] (level %d)", idx, level);
			return;
		}
	}

	cast_kern(desc);

	chunk = desc->chunk;
	cast_kern(chunk);

	pos = idx & mask;
	data = chunk->data[pos];
	if (!data) {
		bpf_spin_unlock(&sdt_task_lock);
		bpf_printk("freeing idx [0x%lx] (%p) without data", idx, &chunk->data[pos]);
		return;
	}

	cast_kern(data);

	data[pos] = (struct sdt_task_data) {
		.tid.gen = data->tid.gen + 1,
		.tptr = 0,
	};

	/* Zero out one word at a time. */
	bpf_for(i, 0, sdt_task_data_size / 8) {
		data->data[i] = 0;
	}

	bpf_for(u, 0, SDT_TASK_LEVELS) {
		level = SDT_TASK_LEVELS - 1 - u;

		/* Only propagate upwards if we are the parent's only free chunk. */
		desc = lv_desc[level];

		sdt_set_idx_state(desc, lv_pos[level], false);

		cast_kern(desc);

		desc->nr_free += 1;
		if (desc->nr_free > 1)
			break;
	}

	bpf_spin_unlock(&sdt_task_lock);

	return;
}

static SDT_TASK_FN_ATTRS
void __arena *sdt_task_retrieve(struct task_struct *p)
{
	struct sdt_task_map_val *mval;

	sdt_arena_verify();

	mval = bpf_task_storage_get(&sdt_task_map, p, 0, 0);
	if (!mval)
		return NULL;

	return (void __arena *)mval->data;
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


static SDT_TASK_FN_ATTRS
int sdt_task_find_empty(struct sdt_task_desc __arena *desc, struct sdt_task_desc * __arena *descp, __u64 *idxp)
{
	struct sdt_task_desc * __arena *desc_children,  __arena *new_chunk;
	struct sdt_task_desc __arena *lv_desc[SDT_TASK_LEVELS];
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_desc __arena *tmp;
	__u64 lv_pos[SDT_TASK_LEVELS];
	__u64 u, pos, level;
	__u64 idx = 0;

	bpf_for(level, 0, SDT_TASK_LEVELS) {
		pos = sdt_chunk_find_empty(desc);

		/* Something has gon terribly wrong. */
		if (pos > SDT_TASK_ENTS_PER_CHUNK)
			return -EINVAL;

		if (pos == SDT_TASK_ENTS_PER_CHUNK)
			return -ENOMEM;

		idx <<= SDT_TASK_ENTS_PER_CHUNK_SHIFT;
		idx |= pos;

		/* Log the levels to complete allocation. */
		lv_desc[level] = desc;
		lv_pos[level] = pos;

		/* The rest of the loop is for internal node traversal. */
		if (level == SDT_TASK_LEVELS - 1)
			break;

		cast_kern(desc);

		chunk = desc->chunk;
		cast_kern(chunk);

		desc_children = (struct sdt_task_desc * __arena *)chunk->descs;
		desc = desc_children[pos];

		/* Someone else is populating the subtree. */
		if (desc == (void *)SDT_TASK_ALLOC_RESERVE)
			return -EAGAIN;

		if (!desc) {
			/* Reserve our spot and go allocate. */
			desc_children[pos] = (void *)SDT_TASK_ALLOC_RESERVE;

			bpf_spin_unlock(&sdt_task_lock);
			new_chunk = sdt_alloc_chunk();
			if (!new_chunk) {
				bpf_printk("%s: allocating new chunk failed", __func__);
				bpf_spin_lock(&sdt_task_lock);
				return -ENOMEM;
			}

			bpf_spin_lock(&sdt_task_lock);

			desc_children[pos] = new_chunk;
			desc = new_chunk;
		}
	}

	bpf_for(u, 0, SDT_TASK_LEVELS) {
		level = SDT_TASK_LEVELS - 1 - u;
		tmp = lv_desc[level];

		cast_kern(tmp);
		sdt_set_idx_state(tmp, lv_pos[level], true);

		tmp->nr_free -= 1;
		if (tmp->nr_free > 0)
			break;

	}

	*descp = desc;
	*idxp = idx;

	return 0;
}

static SDT_TASK_FN_ATTRS
void __arena *sdt_task_alloc(struct task_struct *p)
{
	struct sdt_task_data __arena *data = NULL;
	struct sdt_task_desc __arena *desc;
	struct sdt_task_chunk __arena *chunk;
	struct sdt_task_map_val *mval;
	__u64 idx, pos;
	int ret;

	mval = bpf_task_storage_get(&sdt_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval)
		return NULL;

	bpf_spin_lock(&sdt_task_lock);

	bpf_repeat(SDT_TASK_ALLOCATION_ATTEMPTS) {
		ret = sdt_task_find_empty(sdt_task_desc_root, &desc, &idx);
		if (ret != -EAGAIN)
			break;
	}

	if (ret != 0) {
		bpf_spin_unlock(&sdt_task_lock);
		bpf_printk("%s: error %d on allocation", __func__, ret);
		return NULL;
	}

	cast_kern(desc);

	chunk = desc->chunk;
	cast_kern(chunk);

	/* populate leaf node if necessary */
	pos = idx & (SDT_TASK_ENTS_PER_CHUNK - 1);
	data = chunk->data[pos];
	if (!data) {
		bpf_spin_unlock(&sdt_task_lock);

		data = sdt_task_alloc_from_pool(&sdt_task_data_pool);
		if (!data) {
			sdt_task_free_idx(idx);
			bpf_printk("%s: failed to allocate data from pool", __func__);
			return NULL;
		}

		bpf_spin_lock(&sdt_task_lock);
		chunk->data[pos] = data;
	}

	/* init and return */
	cast_kern(data);

	data->tid.idx = idx;
	data->tptr = (__u64)p;

	mval->tid = data->tid;
	mval->data = data;

	bpf_spin_unlock(&sdt_task_lock);

	return (void __arena *)data->data;
}
