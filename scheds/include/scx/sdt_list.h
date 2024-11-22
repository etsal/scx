/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once
#include "bpf_arena_common.h"

struct arena_list_node;

typedef struct arena_list_node __arena arena_list_node_t;

struct arena_list_node {
	arena_list_node_t	*next;
	u64			padding[2];
	u64			__arena data[];
};

struct arena_list_head {
	struct arena_list_node __arena *first;
};
typedef struct arena_list_head __arena arena_list_head_t;

#ifndef __BPF__
static inline void *bpf_iter_num_new(struct bpf_iter_num *it, int i, int j) { return NULL; }
static inline void bpf_iter_num_destroy(struct bpf_iter_num *it) {}
static inline bool bpf_iter_num_next(struct bpf_iter_num *it) { return true; }
#define cond_break ({})
#define can_loop true
#endif

static inline void list_add_head(arena_list_node_t *n, arena_list_head_t *h)
{
	arena_list_node_t *first = h->first;
	arena_list_node_t * __arena *tmp;

	cast_kern(n);
	WRITE_ONCE(n->next, first);

	tmp = &h->first;
	cast_kern(tmp);
	WRITE_ONCE(*tmp, first);
}

static inline arena_list_node_t *list_pop(arena_list_head_t *h)
{
	arena_list_node_t *first = h->first;
	arena_list_node_t *tmp;
	arena_list_node_t *next;

	if (!first)
		return NULL;

	tmp = first;
	cast_kern(tmp);
	next = tmp->next;

	cast_kern(h);
	WRITE_ONCE(h->first, next);

	return first;
}
