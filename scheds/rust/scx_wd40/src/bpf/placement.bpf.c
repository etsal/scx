/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include <lib/sdt_task.h>

#include "intf.h"
#include "types.h"
#include "lb_domain.h"
#include "deadline.h"

#include <scx/bpf_arena_common.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile bool mempolicy_affinity;

/*
 * Returns the dom mask for a node.
 */
static u64 node_dom_mask(u32 node_id)
{
	u64 mask = 0;
	u32 dom_id = 0;

	bpf_for(dom_id, 0, nr_doms) {
		if (dom_node_id(dom_id) != node_id)
			continue;

		mask |= 1LLU << dom_id;
	}

	return mask;
}

/*
 * Sets the preferred domain mask according to the mempolicy. See man(2)
 * set_mempolicy for more details on mempolicy.
 */
static void task_set_preferred_mempolicy_dom_mask(struct task_struct *p,
						  struct task_ctx *taskc)
{
	struct bpf_cpumask *p_cpumask;
	u32 node_id;
	u32 val = 0;
	void *mask;

	taskc->preferred_dom_mask = 0;

	p_cpumask = lookup_task_bpfmask(p);

	if (!mempolicy_affinity || !bpf_core_field_exists(p->mempolicy) ||
	    !p->mempolicy || !p_cpumask)
		return;

	if (!(p->mempolicy->mode & (MPOL_BIND|MPOL_PREFERRED|MPOL_PREFERRED_MANY)))
		return;

	// MPOL_BIND and MPOL_PREFERRED_MANY use the home_node field on the
	// mempolicy struct, so use that for now. In the future the memory
	// usage of the node can be checked to follow the same algorithm for
	// where memory allocations will occur.
	if ((int)p->mempolicy->home_node >= 0) {
		taskc->preferred_dom_mask =
			node_dom_mask((u32)p->mempolicy->home_node);
		return;
	}

	mask = BPF_CORE_READ(p, mempolicy, nodes.bits);
	if (bpf_core_read(&val, sizeof(val), mask))
		return;

	bpf_for(node_id, 0, nr_nodes) {
		if (!(val & 1 << node_id))
			continue;

		taskc->preferred_dom_mask |= node_dom_mask(node_id);
	}

	return;
}

static u32 task_pick_domain(struct task_ctx *taskc, struct task_struct *p,
			    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();
	u32 first_dom = NO_DOM_FOUND, dom, preferred_dom = NO_DOM_FOUND;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return NO_DOM_FOUND;

	taskc->dom_mask = 0;

	dom = pcpu_ctx[cpu].dom_rr_cur++;
	task_set_preferred_mempolicy_dom_mask(p, taskc);
	bpf_repeat(nr_doms) {
		dom = (dom + 1) % nr_doms;

		if (cpumask_intersects_domain(cpumask, dom)) {
			taskc->dom_mask |= 1LLU << dom;
			/*
			 * The starting point is round-robin'd and the first
			 * match should be spread across all the domains.
			 */
			if (first_dom == NO_DOM_FOUND)
				first_dom = dom;

			if (taskc->preferred_dom_mask == 0)
			       continue;

			if (((1LLU << dom) & taskc->preferred_dom_mask)
			    && preferred_dom == NO_DOM_FOUND)
				preferred_dom = dom;
		}
	}

	return preferred_dom != NO_DOM_FOUND ? preferred_dom: first_dom;
}

__hidden
bool task_set_domain(struct task_struct *p __arg_trusted,
			    u32 new_dom_id, bool init_dsq_vtime)
{
	dom_ptr old_domc, new_domc;
	struct bpf_cpumask *d_cpumask, *t_cpumask;
	struct lb_domain *new_lb_domain;
	struct task_ctx *taskc;
	u32 old_dom_id;

	taskc = lookup_task_ctx_mask(p, &t_cpumask);
	if (!taskc || !t_cpumask) {
		scx_bpf_error("Failed to look up task cpumask");
		return false;
	}

	old_dom_id = taskc->target_dom;
	old_domc = lookup_dom_ctx(old_dom_id);
	if (!old_domc)
		return false;

	if (new_dom_id == NO_DOM_FOUND) {
		bpf_cpumask_clear(t_cpumask);
		return !(p->scx.flags & SCX_TASK_QUEUED);
	}

	new_domc = try_lookup_dom_ctx(new_dom_id);
	if (!new_domc)
		return false;

	new_lb_domain = lb_domain_get(new_dom_id);
	if (!new_lb_domain) {
		scx_bpf_error("no lb_domain for dom%d\n", new_dom_id);
		return false;
	}

	d_cpumask = new_lb_domain->cpumask;
	if (!d_cpumask) {
		scx_bpf_error("Failed to get dom%u cpumask kptr",
			      new_dom_id);
		return false;
	}


	/*
	 * set_cpumask might have happened between userspace requesting LB and
	 * here and @p might not be able to run in @dom_id anymore. Verify.
	 */
	if (bpf_cpumask_intersects(cast_mask(d_cpumask), p->cpus_ptr)) {
		u64 now = scx_bpf_now();

		if (!init_dsq_vtime)
			dom_xfer_task(p, new_dom_id, now);

		taskc->target_dom = new_dom_id;
		taskc->domc = new_domc;

		p->scx.dsq_vtime = dom_min_vruntime(new_domc);
		init_vtime(p, taskc);
		bpf_cpumask_and(t_cpumask, cast_mask(d_cpumask), p->cpus_ptr);
	}

	return taskc->target_dom == new_dom_id;
}

__hidden
void task_pick_and_set_domain(struct task_ctx *taskc,
				     struct task_struct *p,
				     const struct cpumask *cpumask,
				     bool init_dsq_vtime)
{
	u32 dom_id = 0;

	if (nr_doms > 1)
		dom_id = task_pick_domain(taskc, p, cpumask);

	if (!task_set_domain(p, dom_id, init_dsq_vtime))
		scx_bpf_error("Failed to set dom%d for %s[%p]",
			      dom_id, p->comm, p);
}
