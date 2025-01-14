#pragma once

#include <lib/sdt_task.h>

#include "intf.h"

struct lb_domain {
	union sdt_id		tid;

	struct bpf_spin_lock vtime_lock;
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *direct_greedy_cpumask;
	struct bpf_cpumask __kptr *node_cpumask;

	dom_ptr domc;
};

int lb_domain_init(void);
dom_ptr lb_domain_alloc(u32 dom_id);
void lb_domain_free(dom_ptr domc);
struct lb_domain *lb_domain_get(u32 dom_id);
dom_ptr try_lookup_dom_ctx_arena(u32 dom_id);
dom_ptr try_lookup_dom_ctx(u32 dom_id);
dom_ptr lookup_dom_ctx(u32 dom_id);
struct bpf_spin_lock *lookup_dom_vtime_lock(dom_ptr domc);

static inline u64 dom_min_vruntime(dom_ptr domc)
{
	return READ_ONCE_ARENA(u64, domc->min_vruntime);
}

static inline dom_ptr task_domain(struct task_ctx *taskc)
{
	dom_ptr domc = taskc->domc;

	cast_kern(domc);

	return domc;
}

