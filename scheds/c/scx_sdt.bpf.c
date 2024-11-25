/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include <scx/sdt_task_impl.bpf.h>

#include "scx_sdt.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

static SDT_TASK_FN_ATTRS void
stat_inc_enqueue(struct sdt_stats __arena *stats)
{
	cast_kern(stats);
	stats->enqueue += 1;
}
__u64 stat_enqueue;


static SDT_TASK_FN_ATTRS void
stat_global_update(struct sdt_stats __arena *stats)
{
	cast_kern(stats);
	__sync_fetch_and_add(&stat_enqueue, stats->enqueue);
}

s32 BPF_STRUCT_OPS(sdt_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
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
	struct sdt_task_data __arena *data;
	struct sdt_stats __arena *stats;

	data = sdt_task_alloc(p);
	if (!data)
		return -ENOMEM;

	stats = (struct sdt_stats __arena *)data->data;
	stats->pid = p->pid;
	stats->enqueue = 0;

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

	stat_global_update(stats);

	sdt_task_free(p);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init)
{
	int ret;

	ret = sdt_task_init(sizeof(struct sdt_stats));
	if (ret < 0)
		return ret;

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
