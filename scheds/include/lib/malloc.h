#pragma once

int scx_malloc_init(void);
u64 scx_malloc_internal(size_t size);
#define scx_malloc(size) ((void __arena *)scx_malloc_internal((size)))
int scx_free(void *addr);
