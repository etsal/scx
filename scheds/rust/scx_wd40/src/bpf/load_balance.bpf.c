/* Copyright (c) Meta Platforms, Inc. and affiliates. */

/*
 * Load balancing callback in BPF.
 */

#include <scx/common.bpf.h>

#define TIMER_INTERVAL_NS (2ULL * 1000 * 1000 * 1000)

struct timer_wrapper {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_wrapper);
} wd40_timers SEC(".maps");

static int load_balancer_cb(void *map, int key, struct timer_wrapper *timerw)
{

	bpf_timer_start(&timerw->timer, TIMER_INTERVAL_NS, 0);

	return 0;
}

int start_load_balancer(void)
{
	struct timer_wrapper *timerw;
	int timer_id = 0, ret;

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

