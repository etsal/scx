#pragma once

#include "queue.h"

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

struct cpu_ctx {
	bool online;
	u64 cnt_transferable;
	u64 dsq_realtime;
	u64 ts_nonempty;
	/* Used to round robin between timeshare queues. */
	u64 ts_idx;
	u64 ts_ridx;
};

#ifdef __BPF__

struct task_ctx;
typedef struct task_ctx __arena *task_ptr;

struct task_ctx {
	u64 flags;
	struct scx_stats stats;
	u8 prio;
	u64 rqidx;
	TAILQ_ENTRY(task_ptr) runq;
};

/*
 * XXX We have no idle tasks and no real-time tasks, can we just
 * adjust this to 0-255?
 */
#define PRIO_MIN_TIMESHARE 88
#define PRIO_MAX_TIMESHARE 223
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

TAILQ_HEAD(ule_rqhead, task_ptr);

struct ule_runq {
	u64			status;
	struct ule_rqhead	queues[ULE_NRQ];
};

void ule_runq_add(struct ule_runq *rq, task_ptr taskc, int flags, u8 prio);
u8 ule_runq_remove(struct ule_runq *rq, task_ptr taskc, u8 idx);
task_ptr ule_runq_steal(struct ule_runq *rq, int cpu, u8 start);

#else

#endif /* __BPF__ */
