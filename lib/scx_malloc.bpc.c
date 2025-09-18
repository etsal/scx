/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

/*
 * Facade that hides the buddy allocator's implementation details
 * from the caller.
 */

static struct scx_buddy buddy;

__weak
int scx_malloc_init(void)
{
	return scx_buddy_init(&buddy, SCX_BUDDY_MIN_ALLOC_BYTES);
}

u64 scx_malloc_internal(size_t size)
{
	return scx_buddy_alloc_internal(&buddy, size);
}

int scx_free(void __arg_arena *addr)
{
	scx_buddy_free_internal(&buddy, (u64)addr);
	
	return 0;
}


