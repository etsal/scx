// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __BPF__
#ifndef __arena
#define __arena
#endif
#ifndef __arg_arena
#define __arg_arena
#endif
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned short u16;
typedef int s32;
typedef unsigned u32;
typedef long long s64;
typedef unsigned long long u64;
#endif

enum consts {
	CACHELINE_SIZE		= 64,
	MAX_CPUS_SHIFT		= 9,
	MAX_CPUS		= 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8		= MAX_CPUS / 8,
	MAX_TASKS		= 131072,
	MAX_PATH		= 4096,
	MAX_NUMA_NODES		= 64,
	MAX_LLCS		= 64,
	MAX_COMM		= 16,
	MAX_LAYER_MATCH_ORS	= 32,
	/* 64 chars for user-provided name, 64 for possible template suffix. */
	MAX_LAYER_NAME		= 128,
	MAX_LAYERS		= 16,
	MAX_CGROUP_REGEXES	= 16,
	MAX_LAYER_WEIGHT	= 10000,
	MIN_LAYER_WEIGHT	= 1,
	DEFAULT_LAYER_WEIGHT	= 100,
	USAGE_HALF_LIFE		= 100000000,	/* 100ms */
	RUNTIME_DECAY_FACTOR	= 4,
	LAYER_LAT_DECAY_FACTOR	= 32,
	CLEAR_PREEMPTING_AFTER	= 10000000,	/* 10ms */

	DSQ_ID_SPECIAL_MASK	= 0xc0000000,
	HI_FB_DSQ_BASE		= 0x40000000,
	LO_FB_DSQ_BASE		= 0x80000000,

	DSQ_ID_LAYER_SHIFT	= 16,
	DSQ_ID_LLC_MASK		= (1LLU << DSQ_ID_LAYER_SHIFT) - 1,		/* 0x0000ffff */
	DSQ_ID_LAYER_MASK	= ~DSQ_ID_LAYER_SHIFT & ~DSQ_ID_SPECIAL_MASK,	/* 0x3fff0000 */

	/* XXX remove */
	MAX_CGRP_PREFIXES	= 32,

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,

	SCXCMD_OP_NONE 		= 0,
	SCXCMD_OP_JOIN 		= 1,
	SCXCMD_OP_LEAVE 	= 2,

	SCXCMD_PREFIX		= 0x5C10,
	SCXCMD_COMLEN		= 13,
	MAX_GPU_PIDS 		= 100000,

};

enum layer_membership {
	MEMBER_NOEXPIRE		= (u64)-1,
	MEMBER_EXPIRED		= (u64)-2,
	MEMBER_CANTMATCH	= (u64)-3,
	MEMBER_INVALID		= (u64)-4,
};

static inline void ___consts_sanity_check___(void) {
	/* layer->llcs_to_drain uses u64 as LLC bitmap */
	_Static_assert(MAX_LLCS <= 64, "MAX_LLCS too high");
	_Static_assert(MAX_LLCS <= (1 << DSQ_ID_LAYER_SHIFT), "MAX_LLCS too high");
	_Static_assert(MAX_LAYERS <= (DSQ_ID_LAYER_MASK >> DSQ_ID_LAYER_SHIFT) + 1,
		       "MAX_LAYERS too high");
	/* cgroup regex matching uses u64 as match bitmap */
	_Static_assert(MAX_CGROUP_REGEXES <= 64, "MAX_CGROUP_REGEXES too high for u64 bitmap");
}

enum layer_kind {
	LAYER_KIND_OPEN,
	LAYER_KIND_GROUPED,
	LAYER_KIND_CONFINED,
};

enum layer_usage {
	LAYER_USAGE_OWNED,
	LAYER_USAGE_OPEN,
	LAYER_USAGE_SUM_UPTO = LAYER_USAGE_OPEN,

	NR_LAYER_USAGES,
};

/* Statistics */
enum global_stat_id {
	GSTAT_HI_FB_EVENTS,
	GSTAT_HI_FB_USAGE,
	GSTAT_LO_FB_EVENTS,
	GSTAT_LO_FB_USAGE,
	GSTAT_FB_CPU_USAGE,
	GSTAT_ANTISTALL,
	GSTAT_SKIP_PREEMPT,
	GSTAT_FIXUP_VTIME,
	GSTAT_PREEMPTING_MISMATCH,
	NR_GSTATS,
};

enum layer_stat_id {
	LSTAT_SEL_LOCAL,
	LSTAT_ENQ_LOCAL,
	LSTAT_ENQ_WAKEUP,
	LSTAT_ENQ_EXPIRE,
	LSTAT_ENQ_REENQ,
	LSTAT_ENQ_DSQ,
	LSTAT_KEEP,
	LSTAT_MIN_EXEC,
	LSTAT_MIN_EXEC_NS,
	LSTAT_OPEN_IDLE,
	LSTAT_AFFN_VIOL,
	LSTAT_KEEP_FAIL_MAX_EXEC,
	LSTAT_KEEP_FAIL_BUSY,
	LSTAT_PREEMPT,
	LSTAT_PREEMPT_FIRST,
	LSTAT_PREEMPT_XLLC,
	LSTAT_PREEMPT_XNUMA,
	LSTAT_PREEMPT_IDLE,
	LSTAT_PREEMPT_FAIL,
	LSTAT_YIELD,
	LSTAT_YIELD_IGNORE,
	LSTAT_MIGRATION,
	LSTAT_XNUMA_MIGRATION,
	LSTAT_XLLC_MIGRATION,
	LSTAT_XLAYER_WAKE,
	LSTAT_XLAYER_REWAKE,
	LSTAT_LLC_DRAIN_TRY,
	LSTAT_LLC_DRAIN,
	LSTAT_SKIP_REMOTE_NODE,
	NR_LSTATS,
};

enum llc_layer_stat_id {
	LLC_LSTAT_LAT,
	LLC_LSTAT_CNT,
	NR_LLC_LSTATS,
};

/* CPU proximity map from closest to farthest, starts with self */
struct cpu_prox_map {
	u16			cpus[MAX_CPUS];
	u32			core_end;
	u32			llc_end;
	u32			node_end;
	u32			sys_end;
};

struct cpu_ctx {
	s32			cpu;
	bool			current_preempt;
	bool			yielding;
	bool			try_preempt_first;
	bool			is_big;
	s32			preempting_pid;
	u64			preempting_at;

	bool			running_owned;
	bool			running_open;
	bool			running_fallback;
	u64			used_at;
	bool			is_protected;

	u64			layer_usages[MAX_LAYERS][NR_LAYER_USAGES];
	u64			layer_membw_agg[MAX_LAYERS][NR_LAYER_USAGES];
	u64			gstats[NR_GSTATS];
	u64			lstats[MAX_LAYERS][NR_LSTATS];
	u64			ran_current_for;

	u64			usage;

	u64			hi_fb_dsq_id;
	u64			lo_fb_dsq_id;
	bool			in_open_layers;
	u32			layer_id;
	u32			llc_id;
	u32			node_id;
	u32			perf;

	u64			lo_fb_seq;
	u64			lo_fb_seq_at;
	u64			lo_fb_usage_base;

	u32			ogp_layer_order[MAX_LAYERS];	/* open/grouped preempt */
	u32			ogn_layer_order[MAX_LAYERS];	/* open/grouped non-preempt */

	u32			op_layer_order[MAX_LAYERS];	/* open preempt */
	u32			on_layer_order[MAX_LAYERS];	/* open non-preempt */
	u32			gp_layer_order[MAX_LAYERS];	/* grouped preempt */
	u32			gn_layer_order[MAX_LAYERS];	/* grouped non-preempt */

	struct cpu_prox_map	prox_map;
};

struct llc_prox_map {
	u16			llcs[MAX_LLCS];
	u32			node_end;
	u32			sys_end;
};

struct llc_ctx {
	u32			id;
	u64			cpumask;	/* scx_bitmap_t stored as raw pointer */
	u32			nr_cpus;
	u64			vtime_now[MAX_LAYERS];
	u64			queued_runtime[MAX_LAYERS];
	u64			lo_fb_seq;
	u64			lstats[MAX_LAYERS][NR_LLC_LSTATS];
	struct llc_prox_map	prox_map;
};

struct node_ctx {
	u32			id;
	u64			cpumask;	/* scx_bitmap_t stored as raw pointer */
	u32			nr_llcs;
	u32			nr_cpus;
	u64			llc_mask;
};

enum layer_match_kind {
	MATCH_CGROUP_PREFIX,
	MATCH_COMM_PREFIX,
	MATCH_PCOMM_PREFIX,
	MATCH_USED_GPU_PID,
	MATCH_IS_GROUP_LEADER,

	NR_LAYER_MATCH_KINDS,
};

struct layer_match {
	int		kind;
	char		cgroup_prefix[MAX_PATH];
	char		comm_prefix[MAX_COMM];
	char		pcomm_prefix[MAX_COMM];
	bool		used_gpu_pid;
	bool		is_group_leader;
};

struct layer_match_ands {
	struct layer_match	matches[NR_LAYER_MATCH_KINDS];
	int			nr_match_ands;
};

enum layer_growth_algo {
	GROWTH_ALGO_NODE_SPREAD_REVERSE,
	GROWTH_ALGO_NODE_SPREAD_RANDOM,
};

struct layer {
	struct layer_match_ands	matches[MAX_LAYER_MATCH_ORS];
	unsigned int		nr_match_ors;
	unsigned int		id;
	u64			min_exec_ns;
	u64			max_exec_ns;
	u64			yield_step_ns;
	u64			slice_ns;
	bool			fifo;
	u32			weight;

	int			kind;
	bool			preempt;
	bool			preempt_first;
	bool			allow_node_aligned;
	bool			skip_remote_node;
	int			growth_algo;

	u64			nr_tasks;

	u64			cpus_seq;
	u64			node_mask;
	u64			llc_mask;
	bool			check_no_idle;
	u32			perf;
	u64			refresh_cpus;
	u8			cpus[MAX_CPUS_U8];

	u32			nr_cpus;
	u32			nr_llc_cpus[MAX_LLCS];

	u64			llcs_to_drain;
	u32			llc_drain_cnt;

	char			name[MAX_LAYER_NAME];
	bool			is_protected;
	u8			cpuset[MAX_CPUS_U8];
	u64			member_expire_ms;

	u64			arena_cpumask;	/* scx_bitmap_t for layer cpumask */
	u64			arena_cpuset;	/* scx_bitmap_t for layer cpuset */
};

struct cached_cpus {
	s64			id;
	u64			seq;
};

/*
 * Arena bitmap pointers are stored as u64 in this shared header.
 * In BPF code, cast to scx_bitmap_t via the TASKC_*_MASK macros
 * defined in main.bpf.c.
 */
struct task_ctx {
	int			pid;
	int			last_cpu;
	u32			layer_id;
	int			last_waker;
	bool			refresh_layer;
	struct cached_cpus	layered_cpus;
	u64			layered_mask;
	struct cached_cpus	layered_cpus_llc;
	u64			layered_llc_mask;
	struct cached_cpus	layered_cpus_node;
	u64			layered_node_mask;
	struct cached_cpus	layered_cpus_unprotected;
	u64			layered_unprotected_mask;
	u64			cpus_allowed_mask;
	bool			all_cpuset_allowed;
	bool			cpus_node_aligned;
	u64			runnable_at;
	u64			running_at;
	u64			runtime_avg;
	u64			dsq_id;
	u32			llc_id;

	/* for llcc->queue_runtime */
	u32			qrt_layer_id;
	u32			qrt_llc_id;

	u64			recheck_layer_membership;
};

#endif /* __INTF_H */
