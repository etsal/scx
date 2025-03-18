/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include <lib/sdt_task.h>

#include <scx/bpf_arena_common.h>
#include <scx/bpf_arena_spin_lock.h>

#include "cpumask.h"

#include "intf.h"
#include "types.h"
#include "lb_domain.h"
#include "deadline.h"

#include "percpu.h"

#include <scx/bpf_arena_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, int);
	__type(value, int);
} events SEC(".maps");

__weak int start_perf_counter(struct task_struct *p __arg_trusted)
{
	struct bpf_perf_event_value value;
	task_ptr taskc;
	int err;
	u32 id;

	if (!(taskc = lookup_task_ctx(p)))
		return 0;

	id = bpf_get_smp_processor_id();

	err = bpf_perf_event_read_value(&events, id, &value, sizeof(value));
	if (err) {
		scx_bpf_error("counter read error %d", err);
		return 0;
	}

	if (!value.enabled || !value.running)
		return 0;

	bpf_printk("Start %ld", value.counter);
	taskc->counter_start = value.counter;

	return 0;
}

__weak int stop_perf_counter(struct task_struct *p __arg_trusted)
{
	struct bpf_perf_event_value value;
	task_ptr taskc;
	int err;
	u32 id;

	if (!(taskc = lookup_task_ctx(p)))
		return 0;

	id = bpf_get_smp_processor_id();

	err = bpf_perf_event_read_value(&events, id, &value, sizeof(value));
	if (err) {
		scx_bpf_error("counter read error %d", err);
		return 0;
	}

	if (!value.enabled || !value.running)
		return 0;

	taskc->counter_aggregate += value.counter - taskc->counter_start;
	bpf_printk("Delta %ld", taskc->counter_aggregate, taskc->counter_start);

	return 0;
}

