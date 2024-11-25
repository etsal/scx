/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once

#include "sdt_list.h"

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

enum sdt_task_consts {
	SDT_TASK_ALLOC_RESERVE		= 0xbeefcafe,
	SDT_TASK_ENT_PAGE_SHIFT		= 0,
	SDT_TASK_ENT_PAGES		= 1 << SDT_TASK_ENT_PAGE_SHIFT,
	SDT_TASK_ENTS_PER_PAGE_SHIFT	= 9,
	SDT_TASK_ALLOCATION_ATTEMPTS	= 8192,
	SDT_TASK_LEVELS			= 3,
	SDT_TASK_ENTS_PER_CHUNK_SHIFT	= SDT_TASK_ENT_PAGE_SHIFT + SDT_TASK_ENTS_PER_PAGE_SHIFT,
	/*
	 * Skim space off the chunk so that both the chunk and the
	 * allocator linked list are included in the same arena page.
	 */
	SDT_TASK_ENTS_PER_CHUNK		= (1 << SDT_TASK_ENTS_PER_CHUNK_SHIFT) - (16 * sizeof(struct arena_list_node)),
	SDT_TASK_CHUNK_BITMAP_U64S	= div_round_up(SDT_TASK_ENTS_PER_CHUNK, 64),
};

union sdt_task_id {
	__s64				val;
	struct {
		__s32			idx;	/* index in the radix tree */
		__s32			gen;	/* ++'d on recycle so that it forms unique'ish 64bit ID */
	};
};

struct sdt_task_chunk;

/*
 * Each index page is described by the following descriptor which carries the
 * bitmap. This way the actual index can host power-of-two numbers of entries
 * which makes indexing cheaper.
 */
struct sdt_task_desc {
	__u64				allocated[SDT_TASK_CHUNK_BITMAP_U64S];
	__u64				nr_free;
	struct sdt_task_chunk __arena	*chunk;
};

/*
 * Leaf node containing per-task data.
 */
struct sdt_task_data {
	union sdt_task_id		tid;
	__u64				tptr;
	__u64				__arena data[];
};

/*
 * Intermediate node pointing to another intermediate node or leaf node.
 */
struct sdt_task_chunk {
	union {
		struct sdt_task_desc __arena *descs[SDT_TASK_ENTS_PER_CHUNK];
		struct sdt_task_data __arena *data[SDT_TASK_ENTS_PER_CHUNK];
	};
};

struct sdt_task_pool {
	arena_list_head_t		head;
	__u64				elem_size;
	__u64				free_size;
};
