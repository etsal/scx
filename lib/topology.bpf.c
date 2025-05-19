#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/topology.h>

topo_ptr topo_all;

__weak
int topo_contains(topo_ptr topo, u32 cpu)
{
	return scx_bitmap_test_cpu(cpu, topo->mask);
}

static
int topo_subset(topo_ptr topo, scx_bitmap_t mask)
{
	return scx_bitmap_subset(topo->mask, mask);
}

static
topo_ptr topo_node(topo_ptr parent, scx_bitmap_t mask)
{
	topo_ptr topo;

	topo = scx_static_alloc(sizeof(struct topology), 1);
	if (!topo) {
		scx_bpf_error("static allocation failed");
		return NULL;
	}

	topo->parent = parent;
	topo->nr_children = 0;
	topo->level = parent ? topo->parent->level + 1 : 0;
	scx_bitmap_copy(topo->mask, mask);

	if (topo->level >= TOPO_MAX_LEVEL) {
		scx_bpf_error("topology is too deep");
		return NULL;
	}

	return topo;
}


static
int topo_add(topo_ptr parent, scx_bitmap_t mask)
{
	topo_ptr child;

	child = topo_node(parent, mask);
	if (!child)
		return -ENOMEM;

	if (parent->nr_children >= TOPO_MAX_CHILDREN) {
		scx_bpf_error("topology fanout is too large");
		return -EINVAL;
	}

	parent->children[parent->nr_children++] = child;

	return 0;
}

__weak
int topo_init(scx_bitmap_t __arg_arena mask)
{
	struct topo_iter iter;
	topo_ptr topo, child;
	int i;

	if (!topo_all) {
		bpf_printk("\n\n====================START====================");
		topo_all = topo_node(NULL, mask);
		if (!topo_all) {
			scx_bpf_error("couldn't initialize topology");
			return -EINVAL;
		}

		bpf_printk("%s: %d ROOT ADDED SUCCESFULLY", __func__, __LINE__);
		scx_bitmap_print(topo_all->mask);
		bpf_printk("\n");

		return 0;
	}

	bpf_printk("%s, %d", __func__, __LINE__);

	for (topo = topo_all, i = 0; i < TOPO_MAX_LEVEL && can_loop; i++) {
		bpf_printk("%s, %d (LEVEL %d)", __func__, __LINE__, i);
		if (!topo_subset(topo, mask)) {
			bpf_printk("[ERROR] %s, %d", __func__, __LINE__);
			bpf_printk("PARENT");
			scx_bitmap_print(topo->mask);
			bpf_printk("CHILD");
			scx_bitmap_print(mask);

			scx_bpf_error("mask not a subset of a topology node");
			return -EINVAL;
		}

		TOPO_FOR_EACH_CHILD(iter, topo, child) {
			if (topo_subset(child, mask))  {
				bpf_printk("FOUND CANDIDATE CHILD");
				scx_bitmap_print(child->mask);
				break;
			}

			if (scx_bitmap_intersects(child->mask, mask)) {
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
			bpf_printk("%s: %d ADDED SUCCESSFULLY", __func__, __LINE__);
			bpf_printk("PARENT");
			scx_bitmap_print(topo->mask);
			bpf_printk("CHILD");
			scx_bitmap_print(mask);
			bpf_printk("\n");

			return 0;
		}

		topo = child;
	}
	bpf_printk("%s, %d [ERROR IN TOPOLOGY]", __func__, __LINE__);

	scx_bpf_error("topology is too deep");
	return -EINVAL;
}

__weak
topo_ptr topo_find_descendant(topo_ptr topo, u32 cpu)
{
	struct topo_iter iter;
	topo_ptr child;
	int lvl;

	if (!topo_contains(topo, cpu)) {
		scx_bpf_error("missing cpu from topology");
		return NULL;
	}

	for (lvl = 0; lvl < TOPO_MAX_LEVEL && can_loop; lvl++) {
		if (!topo->nr_children)
			return topo;

		TOPO_FOR_EACH_CHILD(iter, topo, child) {
			if (topo_contains(child, cpu))
				break;
		}

		if (!child) {
			scx_bpf_error("missing cpu from inner topology nodes");
			return NULL;
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
	struct topo_iter iter;
	topo_ptr child;

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

__weak
int topo_print(void)
{
	int stack[TOPO_MAX_LEVEL];
	topo_ptr child;
	topo_ptr topo;
	int ind, lvl;

	for (ind = 0; ind < TOPO_MAX_LEVEL && can_loop; ind++) {
		stack[ind] = 0;
	}

	topo = topo_all;
	if (!topo) {
		bpf_printk("[NO TOPOLOGY]");
		return 0;
	}

	lvl = ind = 0;
	bpf_printk("[LEVEL %d, INDEX %d", lvl, ind);
	scx_bitmap_print(topo->mask);

	while (lvl >= 0 && can_loop) {

		ind = stack[lvl]++;

		/* If past the index, go up. */
		if (ind == topo->nr_children) {
			topo = topo_parent;
			stack[lvl] = 0;
			lvl -= 1;
			continue;
		}

		topo = topo->children[ind];
		if (!topo) {
			bpf_printk("[ERROR] No child found");
			return;
		}

		bpf_printk("[LEVEL %d, INDEX %d", lvl, ind);
		scx_bitmap_print(topo->mask);
	}

	return 0;
}
