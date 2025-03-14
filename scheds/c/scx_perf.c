/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>

#include "scx_perf.bpf.skel.h"

const char help_fmt[] =
"A perf sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;
static unsigned long long nproc = 8;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int perf)
{
	exit_req = 1;
}

static void read_stats(struct scx_perf *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static void setup_perf_fds(struct scx_perf *skel, int nfds)
{
	struct perf_event_attr attr;
	const int pid = -1;
	int cpu;
	int ret, fd;

	attr = (struct perf_event_attr) {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_HW_INSTRUCTIONS,
		.sample_period = 1000,
	};

	for (cpu = 0; cpu < nfds; cpu++) {
		fd = syscall(SYS_perf_event_open, &attr, pid, cpu, -1, 0);
		if (fd < 0) {
			perror("perf_event_open");
			exit(1);
		}

		ret = bpf_map_update_elem(bpf_map__fd(skel->maps.events), &cpu,
					&fd, BPF_ANY);
		if (ret) {
			printf("Could not insert cpu%d\n", cpu);
			exit(1);
		}


	}
}

int main(int argc, char **argv)
{
	struct scx_perf *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(perf_ops, scx_perf);

	while ((opt = getopt(argc, argv, "hfn:v")) != -1) {
		switch (opt) {
		case 'n':
			nproc = strtoull(optarg, NULL, 10);
			if (nproc == 0) {
				fprintf(stderr, "failed to parse nprog %s\n", optarg);
				exit(1);
			}

			fprintf(stderr, "Setting cores unsupported\n");
			exit(1);

			break;
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, perf_ops, scx_perf, uei);
	setup_perf_fds(skel, nproc);

	link = SCX_OPS_ATTACH(skel, perf_ops, scx_perf);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];

		read_stats(skel, stats);
		printf("local=%llu global=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_perf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
