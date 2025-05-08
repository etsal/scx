#pragma once

#include "queue.h"

/*
 * XXX We have no idle tasks and no real-time tasks, can we just
 * adjust this to 0-255?
 */
#define PRI_MIN_TIMESHARE 88
#define PRI_MAX_TIMESHARE 223
#define PRI_TIMESHARE_RANGE (PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE + 1)

#define PRIO_MIN -20
#define PRIO_MAX 20
#define SCHED_PRI_NRESV (PRIO_MAX - PRIO_MIN)

#define PRI_INTERACT_RANGE ((PRI_TIMESHARE_RANGE - SCHED_PRI_NRESV) / 2)
#define PRI_BATCH_RANGE (PRI_TIMESHARE_RANGE - PRI_INTERACT_RANGE)

#define PRI_MIN_INTERACT PRI_MIN_TIMESHARE
#define PRI_MAX_INTERACT (PRI_MIN_TIMESHARE + PRI_INTERACT_RANGE - 1)
#define PRI_MIN_BATCH (PRI_MIN_TIMESHARE + PRI_INTERACT_RANGE)
#define PRI_MAX_BATCH PRI_MAX_TIMESHARE

/* Magic values, can be turned into a tunable. */
#define SCHED_SLICE_DEFAULT_DIVISOR	10
#define SCHED_SLICE_MIN_DIVISOR		6

/* Common definitions between BPF and userspace. */

struct scx_stats {
	__u64	enqueue;
	__u64	select_busy_cpu;
	__u64	select_idle_cpu;
};

enum consts {
	NUMA_NODE_ANY		=  -1,
	MAX_CPUS		= 1024,
	ULE_NRQ			= 64,
};

struct task_ctx;
struct ule_runq;
typedef struct task_ctx __arena *task_ptr;

struct task_ctx {
	u64 flags;
	struct scx_stats stats;
	u8 prio;
	u64 rqidx;
	TAILQ_ENTRY(task_ptr) rqptr;
	struct ule_runq *runq;
};

TAILQ_HEAD(ule_rqhead, task_ptr);

struct ule_runq {
	u64			status;
	struct ule_rqhead	queues[ULE_NRQ];
};

struct cpu_ctx {
	bool online;
	u64 dsq_realtime;
	u64 ts_nonempty;
	/* Used to round robin between timeshare queues. */
	u64 idx;
	u64 ridx;
	/* XXX Distinguish between transferrable and total load. */
	u64 load;
	/* XXX Verify that we do need a 64-way runqueue for realtime. */
	struct ule_runq rq_realtime;
	struct ule_runq rq_timeshare;
};
