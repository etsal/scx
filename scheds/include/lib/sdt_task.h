/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once
#include <scx/bpf_arena_common.h>

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

typedef struct sdt_desc __arena sdt_desc_t;

enum sdt_consts {
	SDT_TASK_ENTS_PER_PAGE_SHIFT	= 9,
	SDT_TASK_LEVELS			= 3,
	SDT_TASK_ENTS_PER_CHUNK		= 1 << SDT_TASK_ENTS_PER_PAGE_SHIFT,
	SDT_TASK_CHUNK_BITMAP_U64S	= div_round_up(SDT_TASK_ENTS_PER_CHUNK, 64),
	SDT_TASK_ALLOC_STACK_MIN	= 2 * SDT_TASK_LEVELS + 1,
	SDT_TASK_ALLOC_STACK_MAX	= SDT_TASK_ALLOC_STACK_MIN * 5,
	SDT_TASK_ALLOC_ATTEMPTS		= 128,
};

union sdt_id {
	__s64				val;
	struct {
		__s32			idx;	/* index in the radix tree */
		__s32			gen;	/* ++'d on recycle so that it forms unique'ish 64bit ID */
	};
};

struct sdt_chunk;

/*
 * Each index page is described by the following descriptor which carries the
 * bitmap. This way the actual index can host power-of-two numbers of entries
 * which makes indexing cheaper.
 */
struct sdt_desc {
	__u64				allocated[SDT_TASK_CHUNK_BITMAP_U64S];
	__u64				nr_free;
	struct sdt_chunk __arena	*chunk;
};

/*
 * Leaf node containing per-task data.
 */
struct sdt_data {
	union sdt_id		tid;
	__u64				payload[];
};

/*
 * Intermediate node pointing to another intermediate node or leaf node.
 */
struct sdt_chunk {
	union {
		sdt_desc_t * descs[SDT_TASK_ENTS_PER_CHUNK];
		struct sdt_data __arena *data[SDT_TASK_ENTS_PER_CHUNK];
	};
};

/*
 * Stack structure to avoid chunk allocations/frees while under lock. The
 * allocator preallocates enough arena pages before any operation to satisfy
 * the maximum amount of chunk allocations:(2 * SDT_TASK_LEVELS + 1), two
 * allocations per tree level, and one for the data itself. Preallocating
 * ensures that the stack can satisfy these allocations, so we do not need
 * to drop the lock to allocate pages from the arena in the middle of the
 * top-level alloc. This in turn prevents races and simplifies the code.
 */
struct sdt_alloc_stack {
	__u64 idx;
	void __arena *stack[SDT_TASK_ALLOC_STACK_MAX];
};

struct sdt_pool {
	void				__arena *slab;
	__u64				elem_size;
	__u64				max_elems;
	__u64				idx;
};

struct sdt_stats {
	__u64	chunk_allocs;
	__u64	data_allocs;
	__u64	alloc_ops;
	__u64	free_ops;
	__u64	active_allocs;
	__u64	arena_pages_used;
};

struct sdt_allocator {
	struct sdt_pool pool;
	sdt_desc_t *root;
};

#ifdef __BPF__

void __arena *sdt_task_data(struct task_struct *p);
int sdt_task_init(__u64 data_size);
void __arena *sdt_task_alloc(struct task_struct *p);
void sdt_task_free(struct task_struct *p);
void sdt_arena_verify(void);

int sdt_alloc_init(struct sdt_allocator *alloc, __u64 data_size);
struct sdt_data __arena __arena *sdt_alloc(struct sdt_allocator *alloc);
void sdt_free_idx(struct sdt_allocator *alloc, __u64 idx);

#endif /* __BPF__ */