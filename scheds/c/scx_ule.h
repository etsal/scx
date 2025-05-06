#pragma once
struct scx_stats {
	__u64	enqueue;
	__u64	select_busy_cpu;
	__u64	select_idle_cpu;
};

struct task_ctx {
	u64 flags;
	struct scx_stats stats;
};

typedef struct task_ctx __arena *task_ptr;
