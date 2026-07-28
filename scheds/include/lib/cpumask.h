#pragma once
#include <scx/common.bpf.h>

#include <libarena/bitmap.h>

#define NR_CPU_IDS_UNINIT (~(u32)0)

#define SCXMASK_NBITS BYTES_TO_BITS(512)
#define SCXMASK_NLONG BITS_TO_LONG_LONGS(SCXMASK_NBITS)
#define SCX_BITMAP_NR_LONGS BITS_TO_LONG_LONGS(nr_cpu_ids)
#define SCX_BITMAP_NR_BITS (SCX_BITMAP_NR_LONGS * BITS_PER_LONG_LONG)

struct scx_bitmap_stack {
	u64 bits[SCXMASK_NLONG];
};

typedef struct arena_bitmap __arena * __arg_arena scx_cpumask_t;

const extern volatile u32 nr_cpu_ids;

int scx_idle_init(void);
int scx_idle_import(scx_cpumask_t bitmap, const cpumask_t *bpfmask __arg_trusted);

u64 scx_idle_mask_core_internal(void);
#define scx_idle_mask_core() ((scx_cpumask_t)scx_idle_mask_core_internal())

u64 scx_idle_mask_smt_internal(void);
#define scx_idle_mask_smt() ((scx_cpumask_t)scx_idle_mask_smt_internal())

bool scx_idle_test_and_clear(u32 cpu);
s32 scx_idle_pick(scx_cpumask_t cpus_allowed, u64 flags);
s32 scx_idle_pick_any_cpu(scx_cpumask_t mask);
s32 scx_idle_update(s32 cpu, bool idle);
