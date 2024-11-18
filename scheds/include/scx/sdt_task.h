#pragma once

#include "bpf_arena_common.h"
#include "bpf_arena_list.h"

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

enum sdt_task_consts {
	SDT_TASK_LEVELS			= 1,	/* three levels of internal nodes */
	SDT_TASK_ENTS_PER_CHUNK_SHIFT	= 9,
	SDT_TASK_ENTS_PER_CHUNK		= 1 << SDT_TASK_ENTS_PER_CHUNK_SHIFT,
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
	bool				allocated[SDT_TASK_ENTS_PER_CHUNK];
	__u64				nr_free;
	struct sdt_task_chunk __arena	*chunk;
};

/*
 * Leaf node containing per-task data.
 */
struct sdt_task_data {
	union sdt_task_id		tid;
	__u64				tptr;
	__u64				data[];
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
};
