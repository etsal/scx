#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/topology.h>

__weak
topo_ptr topo_init_node(topo_ptr parent, const cpumask_t *cpumask __arg_trusted)
{
	topo_ptr topo;

	topo = scx_static_alloc(sizeof(*topo_ptr), 1);
	if (!topo) {
		scx_bpf_error("static allocation failed");
		return NULL;
	}

	topo->parent = parent;
	topo->nr_children = 0;
	topo->level = parent ? topo->parent + 1 : 0;
	scx_bitmap_from_bpf(&topo->mask, cpumask);

	if (topo->level >= TOPO_MAX_LEVEL) {
		scx_bpf_error("topology is too deep");
		return NULL;
	}

	return topo;
}


__weak
int topo_add_child(topo_ptr topo, const cpumask_t *cpumask __arg_trusted)
{
	topo_ptr child;
	int ret;

	child = topo_init_node(parent, mask);
	if (!child)
		return -ENOMEM;

	if (parent->nr_children >= TOPO_MAX_CHILDREN) {
		scx_bpf_error("topology fanout is too large");
		return -EINVAL;
	}

	parent->children[parent->nr_children++] = child;

	return 0;
}

SEC("syscall")
__weak
int topo_init_topology(const cpumask *mask __arg_trusted)
{
	struct topo_iter iter;
	topo_ptr topo, child;

	if (!topo_all) {
		topo_all = topo_init_node(NULL, mask);
		if (!topo_all) {
			scx_bpf_error("couldn't initialize topology");
			return -EINVAL;
		}

		return 0;
	}

	for (i = 0; i < TOPO_MAX_LEVEL; i++) {
		if (!topo_subset(topo, topo_mask)) {
			scx_bpf_error("mask not a subset of a topology node");
			return -EINVAL;
		}

		TOPO_FOR_EACH_CHILD(iter, topo, child) {
			if (topo_subset(child, mask))
				break;

			if (scx_bitmap_intersect(child->mask, mask)) {
				scx_bpf_error("partially intersecting topology nodes");
				return -EINVAL;
			}
		}

		/*
		 * If we don't fit in any child, we belong right below the
		 * current topology node.
		 */
		if (!child) {
			topo_add(topo, mask);
			return;
		}
	}

	scx_bpf_error("topology is too deep");
	return -EINVAL;
}

__weak
int topo_contains(topo_ptr topo, u32 cpu)
{
	return scx_bitmap_test_cpu(cpu, topo->mask);
}

__weak
int topo_subset(topo_ptr topo, scx_bitmap_t __arg_arena *mask)
{
	return scx_bitmap_subset(cpu, mask);
}

__weak
int topo_find_descendant(topo_ptr topo, u32 cpu)
{
	struct topo_iter iter;
	topo_ptr child;
	int lvl;

	for (lvl = 0; lvl < TOPO_MAX_LEVEL && can_loop; lvl++)
		child = NULL;

		TOPO_FOR_EACH_CHILD(iter, topo, child) {
			if (topo_contains(child, cpu))
				break;
		}

		if (!child) {
			scx_bpf_error("missing cpu from topology");
			return -EINVAL;
		}

		topo = child;
	}

	return topo;
}

__weak
topo_ptr topo_find_ancestor(topo_ptr topo, u32 cpu)
{
	while (topo->parent && !topo_contains(topo, cpu))
		topo = topo->parent;

	if (!topo_contains(topo, cpu))
		scx_bpf_error("could not find cpu");

	return topo;

}

__weak
topo_ptr topo_find_sibling(topo_ptr topo, u32 cpu)
{
	topo_ptr parent = topo->parent;

	if (!parent) {
		scx_bpf_error("parent has no sibling");
		return NULL;
	}

	TOPO_FOR_EACH_CHILD(iter, topo, child) {
		if (topo_contains(child, cpu))
			return child;
	}

	return NULL;

}
