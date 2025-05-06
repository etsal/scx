#pragma once

/* Common definitions between BPF and userspace. */

struct scx_stats {
	__u64	enqueue;
	__u64	select_busy_cpu;
	__u64	select_idle_cpu;
};

struct cpu_ctx {
	bool online;
	u64 dsq_interactive;
	u64 dsq_timeshare;
};

enum consts {
	NUMA_NODE_ANY		=  -1,
	MAX_CPUS		= 1024,
	/* CPU n owns DSQs 2n, 2n + 1. */
	MAX_DSQ_IDS		= 2 * MAX_CPUS + 1,
};

#ifdef __BPF__

struct task_ctx {
	u64 flags;
	struct scx_stats stats;
};

typedef struct task_ctx __arena *task_ptr;

#else

#endif /* __BPF__ */
