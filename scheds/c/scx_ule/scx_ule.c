/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 * Copyright (c) 2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <sys/sysinfo.h>
#include <linux/limits.h>

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>

#include <scx/common.h>

#include "scx_ule.h"
#include "scx_ule.bpf.skel.h"

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static void set_online_cpus(struct scx_ule *skel)
{
	const char *fmt = "/sys/devices/system/cpu/cpu%d";
	char buf[PATH_MAX];
	int ncpus;
	int i;

	ncpus = sysconf(_SC_NPROCESSORS_CONF);
	skel->bss->nr_cpu_ids = ncpus;

	for (i = 0; i < ncpus; i++) {
		snprintf(buf, PATH_MAX, fmt, i);
		/* If > 0 the file does not exist. */
		if (access(buf, F_OK))
			continue;

		skel->bss->cpu_ctx[i].online = true;
	}
}

int main(int argc, char **argv)
{
	struct scx_ule *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(ule_ops, scx_ule);

	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}


	SCX_OPS_LOAD(skel, ule_ops, scx_ule, uei);

	set_online_cpus(skel);

	link = SCX_OPS_ATTACH(skel, ule_ops, scx_ule);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		printf("====ALLOCATION STATS====\n");
		printf("chunk allocs=%llu\t", skel->bss->alloc_stats.chunk_allocs);
		printf("data_allocs=%llu\n", skel->bss->alloc_stats.data_allocs);
		printf("alloc_ops=%llu\t", skel->bss->alloc_stats.alloc_ops);
		printf("free_ops=%llu\t", skel->bss->alloc_stats.free_ops);
		printf("active_allocs=%llu\t", skel->bss->alloc_stats.active_allocs);
		printf("arena_pages_used=%llu\t", skel->bss->alloc_stats.arena_pages_used);
		printf("\n\n");

		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_ule__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
