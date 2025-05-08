#pragma once

/* Common definitions between BPF and userspace. */

struct scx_stats {
	__u64	enqueue;
	__u64	select_busy_cpu;
	__u64	select_idle_cpu;
};

struct cpu_ctx {
	bool online;
	u64 cnt_transferable;
	u64 dsq_realtime;
	u64 dsq_timeshare[CPU_DSQS];
	u64 ts_nonempty;
	/* Used to round robin between timeshare queues. */
	u64 ts_idx;
	u64 ts_ridx;
};

enum consts {
	NUMA_NODE_ANY		=  -1,
	MAX_CPUS		= 1024,
	CPU_BATCH_DSQS		= 64,
	/* Each CPU has CPU_BATCH_DSQs and a realtime DSQ. */
	CPU_DSQS		= CPU_BATCH_DSQS + 1,
	MAX_DSQ_IDS		= CPU_DSQS * MAX_CPUS,
};

#ifdef __BPF__

struct task_ctx {
	u64 flags;
	struct scx_stats stats;
	u64 prio;
	u64 dsq;
};

typedef struct task_ctx __arena *task_ptr;

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

#else

#endif /* __BPF__ */
