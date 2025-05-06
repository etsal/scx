/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.h>
#include <lib/sdt_task.h>

#include "scx_ule.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define DEFINE_SDT_STAT(metric)			\
static inline void				\
stat_inc_##metric(task_ptr taskc)		\
{						\
	taskc->stats.metric += 1;		\
}						\
__u64 stat_##metric;				\

DEFINE_SDT_STAT(enqueue);
DEFINE_SDT_STAT(select_idle_cpu);
DEFINE_SDT_STAT(select_busy_cpu);

volatile int nr_cpu_ids;
struct cpu_ctx cpu_ctx[MAX_CPUS];

/* XXX We have no policy yet so just use the DSQ from teh first CPU. */
#define SHARED_DSQ (0)

static struct cpu_ctx *lookup_cpu_ctx(s32 cpu)
{
	if (cpu >= nr_cpu_ids || cpu >= MAX_CPUS) {
		scx_bpf_error("Failed to lookup cpu ctx for %d", cpu);
		return NULL;
	}

	return &cpu_ctx[cpu];
}

s32 BPF_STRUCT_OPS(sdt_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	task_ptr taskc;
	bool is_idle = false;
	s32 cpu;

	taskc = scx_task_data(p);
	if (!taskc) {
		scx_bpf_error("%s: no context for pid %d", __func__, p->pid);
		return 0;
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc_select_idle_cpu(taskc);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	} else {
		stat_inc_select_busy_cpu(taskc);
	}

	return cpu;
}

void BPF_STRUCT_OPS(sdt_enqueue, struct task_struct *p, u64 enq_flags)
{
	task_ptr taskc ;

	taskc = scx_task_data(p);
	if (!taskc) {
		scx_bpf_error("%s: no stats for pid %d", __func__, p->pid);
		return;
	}

	stat_inc_enqueue(taskc);

	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(sdt_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	task_ptr taskc;

	taskc = scx_task_alloc(p);
	if (!taskc) {
		scx_bpf_error("arena allocator out of memory");
		return -ENOMEM;
	}

	return 0;
}

void BPF_STRUCT_OPS(sdt_exit_task, struct task_struct *p,
			      struct scx_exit_task_args *args)
{
	scx_task_free(p);
}

static s32 cpu_init(s32 cpu)
{
	struct cpu_ctx *cpu_ctx;
	int ret;

	cpu_ctx = lookup_cpu_ctx(cpu);
	if (!cpu_ctx)
		return -ENOENT;

	if (!cpu_ctx->online)
		return 0;

	cpu_ctx->dsq_interactive = 2 * cpu;
	cpu_ctx->dsq_timeshare = 2 * cpu + 1;

	ret = scx_bpf_create_dsq(cpu_ctx->dsq_interactive, NUMA_NODE_ANY);
	if (ret) {
		scx_bpf_error("cpu %d: error %d on dsq_interactive creation", cpu, ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(cpu_ctx->dsq_interactive, NUMA_NODE_ANY);
	if (ret) {
		scx_bpf_error("cpu %d: error %d on dsq_interactive creation", cpu, ret);
		return ret;
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sdt_init)
{
	int ret, i;

	ret = scx_task_init(sizeof(struct task_ctx));
	if (ret < 0) {
		scx_bpf_error("%s: failed with %d", __func__, ret);
		return ret;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		ret = cpu_init(i);
		if (ret)
			return ret;
	}

	return 0;
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
