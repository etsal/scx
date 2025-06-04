/* Copyright (c) Meta Platforms, Inc. and affiliates. */

/*
 * Load balancing callback in BPF.
 */

#include <scx/common.bpf.h>

#define TIMER_INTERVAL_NS (2ULL * 1000 * 1000 * 1000)
#define PULL_THRESHOLD (

struct timer_wrapper {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_wrapper);
} wd40_timers SEC(".maps");

scx_minheap_t *hpusher;
scx_minheap_t *hpuller;

/* 
 * XXX For nodes, still use load_balance_one but with a different way of initializing
 * the min heaps. We calculate the aggregate load for each node by traversing
 * its LLC, then for each pusher and puller node pair we populate the minheaps
 * with their domains. We then keep transferring until we transfer the 
 */

/*
 * XXXMISSING: 
 *	- Proper load calculation for domains
 *	- Making sure we can grab domc from the topology
 *	- Adding thresholds for pushing and pulling
 *	- Starting the timer from wd40_init()
 */

static
int load_balance_one(void)
{
	struct scx_minheap_elem helem;
	u64 lpusher, lpuller;
	dom_ptr pusher;
	dom_ptr puller;

	/* If we can't pop anymore, clean up the heaps. */
	if (scx_minheap_empty(hpusher) || scx_minheap_empty(hpuller)) {
		scx_minheap_invalidate(hpusher);
		scx_minheap_invalidate(hpuller);
		return 0;
	}

	ret = scx_minhead_pop(hpusher, &helem);
	if (ret)
		return ret;
	pusher = (dom_ptr)helem.elem;
	lpusher = ULONG_MAX - helem.weight;

	ret = scx_minhead_pop(hpuller, &helem);
	if (ret)
		return ret;
	puller = (dom_ptr)helem.elem;
	lpuller = helem.weight;

	/* If we can't push or pull anymore, we're done. */
	if (puller above threshold or pusher below threshold)
		return 0;

	/* XXX If the puller/pusher are below an imbalance threshold then stop. */
	while (puller is below threshold && pusher is above threshold) {

		/* If we have no more tasks to push, then stop. */
		if (pusher.active_tasks.read_idx == pusher.active_tasks.write_idx)
			break;
		
		taskc = pusher.active_tasks[pusher.active_tasks.read_idx];
		pusher.active_tasks.read_idx += 1;
		pusher.active_tasks.read_idx %= MAX_DOM_ACTIVE_TPTRS;

		/* 
		 * If task is valid, transfer (XXX How do we know? Ideally
		 * we keep our index in the active_task ring buffer and 
		 * scrub it on exit if the entry stil has our taskc. If 
		 * we see an invalid task, we ignore it.)
		 */
		if (!task is valid)
			continue;

		/* XXX If task has a cpumask, leave it where it is. */

		/* XXX Change the target dom and last migration for the task. */

		/* XXX Properly calculate task load. */

		/* XXX Adjust pusher/puller loads. */

		lpuller += task.weight;
		lpusher -= task.weight;
	}

	/* 
	 * If both the pusher and the puller are still capable of, the pusher
	 * is unable to push further tasks. Do not reconsider it for balancing.
	 */
	if (!pusher below threshold && pusher has active tasks && puller is below threshold) {
		err = scx_minheap_insert(hpusher, (u64)pusher, ULONG_MAX - lpusher);
		if (!err)
			return err;
	}

	if (!puller above threshold && pusher has active tasks) {
		err = scx_minheap_insert(hpusher, (u64)pusher, ULONG_MAX - lpusher);
		if (!err)
			return err;
	}

	return -EAGAIN;
}


static 
int load_balancer_cb(void *map, int key, struct timer_wrapper *timerw)
{
	struct topo_iter iter;
	u64 total_load = 0;
	topo_ptr topo;
	dom_ptr domc;

	/* Sort all domains by load. */
	TOPO_FOR_EACH_LLC(&iter, topo) {
		domc = (dom_ptr)topo->data;
		load = lb_load(domc);
		total_load += load;

		/* Insert each domain to both heaps. */
		scx_minhead_insert(hpuller, (u64)domc, load);
		scx_minhead_insert(hpusher, (u64)domc, ULONG_MAX - load);
	}


	while (can_loop) {
		ret = load_balance_one();
		if (ret != -EAGAIN)
			break;
	}

	if (ret < 0) {
		scx_bpf_error("timer error %d", ret);
		return ret;
	}

	/* XXX Clean up the heaps. */
	scx_minheap_invalidate(hpusher);
	scx_minheap_invalidate(hpuller);

	/* 
	 * XXX Ideally we still emit stats. This is not much of an issue both nodes and
	 * domains can have stat entries node/imbal/delta that we print by the end
	 * of the load balancing. Also print out how much time it took to load balance.
	 */

	bpf_timer_start(&timerw->timer, TIMER_INTERVAL_NS, 0);

	return 0;


}

int start_load_balancer(void)
{
	struct timer_wrapper *timerw;
	int timer_id = 0, ret;

	hpusher = scx_minheap_alloc(MAX_DOMAINS);
	if (!hpusher)
		return -ENOMEM;

	hpuller = scx_minheap_alloc(MAX_DOMAINS);
	if (!hpuller)
		return -ENOMEM;

	timerw = bpf_map_lookup_elem(&load_balancer_data, &timer_id);
	if (!timerw) {
		scx_bpf_error("Failed to lookup layered timer");
		return -ENOENT;
	}

	ret = bpf_timer_init(&timerw->timer, NULL, CLOCK_MONOTONIC);
	if (ret < 0) {
		scx_bpf_error("can't happen");
		return -ENOENT;
	}

	ret = bpf_timer_set_callback(&timerw->timer, &load_balancer_cb);
	if (ret < 0) {
		scx_bpf_error("can't happen");
		return -ENOENT;
	}

	err = bpf_timer_start(&timerw->timer, TIMER_INTERVAL_NS, 0);
	if (err < 0) {
		scx_bpf_error("can't happen");
		return -ENOENT;
	}

	return 0;
}

