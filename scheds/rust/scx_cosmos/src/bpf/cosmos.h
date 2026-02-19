#pragma once

#include <lib/topology.h>

typedef struct task_ctx __arena task_ctx;

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_update;
	u64 perf_lvl;
	u64 perf_events;

	topo_ptr topo;
};

typedef struct cpu_ctx __arena cpu_ctx;

struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu);
bool is_cpu_idle(s32 cpu);

bool is_event_heavy(const task_ctx *tctx);
int start_counters(s32 cpu);
void stop_counters(struct task_struct *p, task_ctx *tctx, s32 cpu);

int timer_init(void);
