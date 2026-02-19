#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#include "intf.h"
#include "params.h"
#include "cosmos.h"

/*
 * Timer used to defer idle CPU wakeups.
 *
 * Instead of triggering wake-up events directly from hot paths, such as
 * ops.enqueue(), idle CPUs are kicked using the wake-up timer.
 */
struct wakeup_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct wakeup_timer);
} wakeup_timer SEC(".maps");

/*
 * Kick idle CPUs with pending tasks.
 *
 * Instead of waking up CPU when tasks are enqueued, we defer the wakeup
 * using this timer handler, in order to have a faster enqueue hot path.
 */
static int wakeup_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;
	int err;

	/*
	 * Iterate over all CPUs and wake up those that have pending tasks
	 * in their local DSQ.
	 *
	 * Note that tasks are only enqueued in ops.enqueue(), but we never
	 * wake-up the CPUs from there to reduce overhead in the hot path.
         */
	bpf_for(cpu, 0, nr_cpu_ids)
		if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) && is_cpu_idle(cpu))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	/*
	 * Re-arm the wakeup timer.
	 */
	err = bpf_timer_start(timer, slice_ns, 0);
	if (err)
		scx_bpf_error("Failed to re-arm wakeup timer");

	return 0;
}

__weak
int timer_init(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	if (!deferred_wakeups)
		return 0;

	timer = bpf_map_lookup_elem(&wakeup_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup wakeup timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &wakeup_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, wakeup_timerfn);

	err = bpf_timer_start(timer, slice_ns, 0);
	if (err) {
		scx_bpf_error("Failed to arm wakeup timer");
		return err;
	}

	return 0;
}
