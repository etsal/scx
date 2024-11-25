#pragma once
struct sdt_stats {
	int	seq;
	pid_t	pid;
	__u64	init;
	__u64	enqueue;
	__u64	exit;
};
