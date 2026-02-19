#pragma once
/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	1024

/*
 * Maximum amount of NUMA nodes supported by the scheduler.
 */
#define MAX_NODES	1024

/*
 * Maximum amount of GPUs supported by the scheduler.
 */
#define MAX_GPUS	32

/*
 * Shared DSQ used to schedule tasks in deadline mode when the system is
 * saturated.
 *
 * When system is not saturated tasks will be dispatched to the local DSQ
 * in round-robin mode.
 */
#define SHARED_DSQ		0

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPU).
 */
const volatile __weak bool primary_all = true;

/*
 * Enable flat iteration to find idle CPUs (fast but inaccurate).
 */
const volatile __weak bool flat_idle_scan = false;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile __weak bool smt_enabled = true;

/*
 * Enable preferred cores prioritization.
 */
const volatile __weak bool preferred_idle_scan = false;

/*
 * CPUs sorted by their capacity in descendent order.
 */
const volatile __weak u64 preferred_cpus[MAX_CPUS];

/*
 * Cache CPU capacity values.
 */
const volatile __weak u64 cpu_capacity[MAX_CPUS];

/*
 * Enable cpufreq integration.
 */
const volatile __weak bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizations.
 */
const volatile __weak bool numa_enabled;

/*
 * Aggressively try to avoid SMT contention.
 *
 * Default to true here, so veristat takes the more complicated path.
 */
const volatile __weak bool avoid_smt = true;

/*
 * Enable address space affinity.
 */
const volatile __weak bool mm_affinity;

/*
 * Enable perf-event scheduling.
 */
const volatile __weak bool perf_enabled;

/*
 * Performance counter threshold to classify a task as event heavy.
 */
const volatile __weak u64 perf_threshold;

/*
 * Enable deferred wakeup.
 */
const volatile __weak bool deferred_wakeups = true;

/*
 * Do we want to keep the tasks sticky or distribute them on being event
 * heavy
 */
const volatile __weak bool perf_sticky;

/*
 * Ignore synchronous wakeup events.
 */
const volatile __weak bool no_wake_sync;

/*
 * Default time slice.
 */
const volatile __weak u64 slice_ns = 10000ULL;

/*
 * Maximum runtime that can be charged to a task.
 */
const volatile __weak u64 slice_lag = 20000000ULL;

/*
 * User CPU utilization threshold to determine when the system is busy.
 */
const volatile __weak u64 busy_threshold;

/*
 * Current global CPU utilization percentage in the range [0 .. 1024].
 */
volatile __weak u64 cpu_util;

/*
 * Scheduler statistics.
 */
volatile __weak u64 nr_event_dispatches;

/*
 * Maximum amount of cpus supported by the system.
 */
const volatile __weak u32 nr_cpu_ids;

/*
 * Maximum possible NUMA node number.
 */
const volatile __weak u32 nr_node_ids;
