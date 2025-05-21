/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__uint(max_entries, 1 << 16); /* number of pages */
        __ulong(map_extra, (1ull << 32)); /* start of mmap() region */
#else
	__uint(max_entries, 1 << 20); /* number of pages */
        __ulong(map_extra, (1ull << 44)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");

/*
 * Task BPF map entry recording the task's assigned ID and pointing to the data
 * area allocated in arena.
 */
struct scx_task_map_val {
	union sdt_id		tid;
	__u64			tptr;
	struct sdt_data __arena	*data;
};

typedef struct scx_task_map_val __arena scx_task_map_val_t;

/* XXX Hack, will replace with sth nicer. */
#define ARENA_ARRSZ (10000000)
scx_task_map_val_t *scx_task_map;

struct scx_allocator scx_task_allocator;

__hidden
void __arena *scx_task_alloc(struct task_struct *p)
{
	struct sdt_data __arena *data = NULL;
	scx_task_map_val_t *mval;

	mval = &scx_task_map[p->pid];

	data = scx_alloc(&scx_task_allocator);

	mval->tid = data->tid;
	mval->tptr = (__u64) p;
	mval->data = data;

	return (void __arena *)data->payload;
}

__hidden
int scx_task_init(__u64 data_size)
{
	size_t npages;
	int ret;

	npages = div_round_up(sizeof(*scx_task_map) * ARENA_ARRSZ, PAGE_SIZE);
	scx_task_map = bpf_arena_alloc_pages(&arena, NULL,
					npages,
					NUMA_NO_NODE, 0);
	if (!scx_task_map)
		return -ENOMEM;

	ret = scx_alloc_init(&scx_task_allocator, data_size);
	if (ret)  {
		bpf_arena_free_pages(&arena, scx_task_map, npages);
		scx_task_map = NULL;
	}

	return ret;
}

__hidden
void __arena *scx_task_data(struct task_struct *p)
{
	struct sdt_data __arena *data;
	scx_task_map_val_t *mval;

	scx_arena_subprog_init();
	
	mval = &scx_task_map[p->pid];
	data = mval->data;

	return (void __arena *)data->payload;
}

__hidden
void scx_task_free(struct task_struct *p)
{
	scx_task_map_val_t *mval;

	scx_arena_subprog_init();

	/* This causes the mval to be demoted to a scalar. I have no idea why. */
	mval = &scx_task_map[p->pid];

	scx_alloc_free_idx(&scx_task_allocator, scx_task_map[p->pid].tid.idx);
	scx_task_map[p->pid].data = NULL;
	scx_task_map[p->pid].tptr = 0;
}
