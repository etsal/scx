/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifndef __LAYERED_UTIL_H
#define __LAYERED_UTIL_H

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern const volatile u32 debug;

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

bool match_prefix(const char __arg_arena __arena *prefix, const char *str);
char *format_cgrp_path(struct cgroup *cgrp);

#endif /* __LAYERED_UTIL_H */
