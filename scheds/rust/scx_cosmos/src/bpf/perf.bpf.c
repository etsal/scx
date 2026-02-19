#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#include "intf.h"
#include "params.h"
#include "cosmos.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, MAX_CPUS);
} perf_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(value_size, sizeof(struct bpf_perf_event_value));
	__uint(key_size, sizeof(u32));
	__uint(max_entries, 1);
} start_readings SEC(".maps");

static int read_perf_counter(s32 cpu, u32 counter_idx, struct bpf_perf_event_value *value)
{
	u32 key = cpu + counter_idx;

	return bpf_perf_event_read_value(&perf_events, key, value, sizeof(*value));
}

__weak
int start_counters(s32 cpu)
{
	struct bpf_perf_event_value value;
	struct bpf_perf_event_value *ptr;
	u32 i;

	i = 0;
	ptr = bpf_map_lookup_elem(&start_readings, &i);
	if (ptr) {
		if (read_perf_counter(cpu, i, &value) == 0)
			*ptr = value;
		else
			__builtin_memset(ptr, 0, sizeof(*ptr));
	}

	return 0;
}

__weak
void stop_counters(struct task_struct __arg_trusted *p, task_ctx __arg_arena *tctx, s32 cpu)
{
	struct bpf_perf_event_value current, *start;
	struct cpu_ctx *cctx;
	u64 delta_events = 0, delta = 0;
	u32 i = 0;

	start = bpf_map_lookup_elem(&start_readings, &i);
	if (start && start->counter != 0) {
		if (read_perf_counter(cpu, i, &current) == 0) {
			if (current.counter >= start->counter)
				delta = current.counter - start->counter;
			delta_events = delta;
		}
	}

	tctx->perf_events = delta_events;
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;
	cctx->perf_events += delta;

}

/*
 * Return true if the task is triggering too many PMU events.
 */
__weak
bool is_event_heavy(const task_ctx __arg_arena *tctx)
{
	return tctx->perf_events > perf_threshold;
}
