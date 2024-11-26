/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

#include "../sdt/sdt_task.bpf.c"

#include "scx_sdt.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

#define DEFINE_SDT_STAT(metric)				\
static SDT_TASK_FN_ATTRS void				\
stat_inc_##metric(struct sdt_stats __arena *stats)	\
{							\
	cast_kern(stats);				\
	stats->metric += 1;				\
}							\
__u64 stat_##metric;					\

DEFINE_SDT_STAT(enqueue);
DEFINE_SDT_STAT(init);
DEFINE_SDT_STAT(exit);
DEFINE_SDT_STAT(select_idle_cpu);
DEFINE_SDT_STAT(select_busy_cpu);

static SDT_TASK_FN_ATTRS void
stat_global_update(struct sdt_stats __arena *stats)
{
	cast_kern(stats);
	__sync_fetch_and_add(&stat_enqueue, stats->enqueue);
	__sync_fetch_and_add(&stat_init, stats->init);
	__sync_fetch_and_add(&stat_exit, stats->exit);
	__sync_fetch_and_add(&stat_select_idle_cpu, stats->select_idle_cpu);
	__sync_fetch_and_add(&stat_select_busy_cpu, stats->select_busy_cpu);
}

s32 BPF_STRUCT_OPS(sdt_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct sdt_stats __arena *stats;
	bool is_idle = false;
	s32 cpu;

	stats = sdt_task_retrieve(p);
	if (!stats) {
		bpf_printk("%s: no stats for pid %d", p->pid);
		return 0;
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc_select_idle_cpu(stats);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	} else {
		stat_inc_select_busy_cpu(stats);
	}

	return cpu;
}

void BPF_STRUCT_OPS(sdt_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct sdt_stats __arena *stats;

	stats = sdt_task_retrieve(p);
	if (!stats) {
		bpf_printk("%s: no stats for pid %d", p->pid);
		return;
	}

	stat_inc_enqueue(stats);

	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(sdt_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct sdt_stats __arena *stats;

	stats = sdt_task_alloc(p);
	if (!stats) {
		bpf_printk("arena allocator out of memory");
		return -ENOMEM;
	}

	stats->pid = p->pid;

	stat_inc_init(stats);

	return 0;
}

void BPF_STRUCT_OPS(sdt_exit_task, struct task_struct *p,
			      struct scx_exit_task_args *args)
{
	struct sdt_stats __arena *stats;

	stats = sdt_task_retrieve(p);
	if (!stats) {
		bpf_printk("%s: no stats for pid %d", p->pid);
		return;
	}

	stat_inc_exit(stats);
	stat_global_update(stats);

	sdt_task_free(p);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init)
{
	int ret;

	ret = sdt_task_init(sizeof(struct sdt_stats));
	if (ret < 0) {
		bpf_printk("sdt_init failed with %d", ret);
		return ret;
	}

	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(sdt_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(sdt_ops,
	       .select_cpu		= (void *)sdt_select_cpu,
	       .enqueue			= (void *)sdt_enqueue,
	       .dispatch		= (void *)sdt_dispatch,
	       .init_task		= (void *)sdt_init_task,
	       .exit_task		= (void *)sdt_exit_task,
	       .init			= (void *)sdt_init,
	       .exit			= (void *)sdt_exit,
	       .name			= "sdt");
