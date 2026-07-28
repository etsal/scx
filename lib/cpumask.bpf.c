#include <libarena/common.h>
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/percpu.h>
#include <lib/topology.h>

const volatile u32 nr_cpu_ids = NR_CPU_IDS_UNINIT;

static __always_inline s32
scx_bitmap_pick_any_cpu_once(scx_cpumask_t mask, u64 __arg_arena *start)
{
	u64 old;
	u64 ind, i, nr_longs = SCX_BITMAP_NR_LONGS;
	s32 cpu;

	if (unlikely(nr_longs > SCXMASK_NLONG))
		return -EINVAL;

	bpf_for (i, 0, SCXMASK_NLONG) {
		if (i >= nr_longs)
			break;

		ind = (*start + i) % nr_longs;

		old = mask->bits[ind];
		if (!old)
			continue;

		cpu = arena_ffs(old);
		if (!bmp_test_and_clear_bit(ind * BITS_PER_LONG_LONG + cpu, mask))
			return -EAGAIN;

		*start = ind;

		return ind * 64 + cpu;
	}

	return -EBUSY;
}

__weak s32
scx_idle_pick_any_cpu(scx_cpumask_t mask)
{
	u64 zero = 0;
	s32 cpu;

	do {
		cpu = scx_bitmap_pick_any_cpu_once(mask, &zero);
	} while (cpu == -EAGAIN && can_loop);

	return cpu;
}

static scx_cpumask_t mask_idle_core;
static scx_cpumask_t mask_idle_smt;
static bool smt_active;

static __always_inline s32
scx_idle_any_and(scx_cpumask_t a, scx_cpumask_t b)
{
	u64 nr_longs = SCX_BITMAP_NR_LONGS;
	u64 word;
	int i;

	if (unlikely(nr_longs > SCXMASK_NLONG))
		return -EINVAL;

	for (i = zero; i < nr_longs && can_loop; i++) {
		word = a->bits[i] & b->bits[i];
		if (word)
			return i * BITS_PER_LONG_LONG + arena_ffs(word);
	}

	return -EBUSY;
}

static __always_inline topo_ptr scx_idle_cpu_core(s32 cpu)
{
	topo_ptr cpu_node;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return NULL;

	cpu_node = (topo_ptr)topo_nodes[TOPO_CPU][cpu];
	if (!cpu_node || cpu_node->level != TOPO_CPU || !cpu_node->parent ||
	    cpu_node->parent->level != TOPO_CORE)
		return NULL;

	return cpu_node->parent;
}

static __always_inline int scx_idle_set_smt(topo_ptr core, bool idle)
{
	topo_ptr sibling;
	s32 sibling_cpu;
	int i;

	for (i = zero; i < core->nr_children && can_loop; i++) {
		sibling = core->children[i];
		if (!sibling || sibling->level != TOPO_CPU)
			return -EINVAL;

		sibling_cpu = sibling->level_ids[TOPO_CPU];
		if (sibling_cpu < 0 || sibling_cpu >= nr_cpu_ids)
			return -EINVAL;

		if (idle)
			bmp_set_bit(sibling_cpu, mask_idle_smt);
		else
			bmp_clear_bit(sibling_cpu, mask_idle_smt);
	}

	return 0;
}

static __always_inline bool scx_idle_core_is_idle(topo_ptr core)
{
	topo_ptr sibling;
	s32 sibling_cpu;
	int i;

	for (i = zero; i < core->nr_children && can_loop; i++) {
		sibling = core->children[i];
		if (!sibling || sibling->level != TOPO_CPU)
			return false;

		sibling_cpu = sibling->level_ids[TOPO_CPU];
		if (sibling_cpu < 0 || sibling_cpu >= nr_cpu_ids ||
		    !bmp_test_bit(sibling_cpu, mask_idle_core))
			return false;
	}

	return true;
}

__weak
int scx_idle_init(void)
{
	scx_cpumask_t idle_core, idle_smt;
	topo_ptr root = topo_all;
	u32 mask_bits;

	if (nr_cpu_ids == NR_CPU_IDS_UNINIT)
		return -ENOENT;
	mask_bits = round_up(nr_cpu_ids, 64);
	if (!root || root->level != TOPO_TOP || !root->mask)
		return -ENOENT;
	if (mask_idle_core || mask_idle_smt)
		return -EALREADY;

	idle_core = bmp_alloc(mask_bits);
	idle_smt = bmp_alloc(mask_bits);
	if (!idle_core || !idle_smt) {
		if (idle_core)
			arena_free(idle_core);
		if (idle_smt)
			arena_free(idle_smt);
		return -ENOMEM;
	}

	bmp_copy(mask_bits, idle_core, root->mask);
	bmp_copy(mask_bits, idle_smt, root->mask);

	mask_idle_core = idle_core;
	mask_idle_smt = idle_smt;
	smt_active = topo_max_children[TOPO_CORE] > 1;

	return 0;
}

__weak int
scx_idle_import(scx_cpumask_t bitmap, const cpumask_t *bpfmask __arg_trusted)
{
	u64 nr_longs = SCX_BITMAP_NR_LONGS;
	int i;

	for (i = 0; i < sizeof(cpumask_t) / sizeof(u64) && can_loop; i++) {
		if (i >= nr_longs)
			break;
		bitmap->bits[i] = bpfmask->bits[i];
	}

	return 0;
}

__weak u64
scx_idle_mask_core_internal(void)
{
	return (u64)mask_idle_core;
}

__weak u64
scx_idle_mask_smt_internal(void)
{
	return (u64)mask_idle_smt;
}

__weak
bool scx_idle_test_and_clear(u32 cpu)
{
	topo_ptr core;
	scx_cpumask_t smts;

	if (smt_active) {
		core = scx_idle_cpu_core(cpu);
		if (!core)
			return false;
		smts = core->mask;

		if (bmp_intersects(nr_cpu_ids, mask_idle_smt, smts)) {
			if (scx_idle_set_smt(core, false))
				return false;
		} else if (bmp_test_bit(cpu, mask_idle_smt)) {
			__bmp_clear_bit(cpu, mask_idle_smt);
		}
	}

	return bmp_test_and_clear_bit(cpu, mask_idle_core);
}

__weak s32
scx_idle_pick(scx_cpumask_t cpus_allowed, u64 flags)
{
	int cpu;

	do {
		if (smt_active) {
			cpu = scx_idle_any_and(mask_idle_smt, cpus_allowed);
			if (cpu >= 0)
				goto found;

			if (flags & SCX_PICK_IDLE_CORE)
				return -EBUSY;
		}

		cpu = scx_idle_any_and(mask_idle_core, cpus_allowed);
		if (cpu < 0)
			return -EBUSY;

found:
		;
	} while (!scx_idle_test_and_clear(cpu) && can_loop);

	return cpu;
}

__weak s32
scx_idle_update(s32 cpu, bool idle)
{
	topo_ptr core;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	if (!mask_idle_core || !mask_idle_smt)
		return -ENODEV;

	if (!smt_active) {
		if (idle) {
			bmp_set_bit(cpu, mask_idle_core);
			bmp_set_bit(cpu, mask_idle_smt);
		} else {
			bmp_clear_bit(cpu, mask_idle_core);
			bmp_clear_bit(cpu, mask_idle_smt);
		}
		return 0;
	}

	core = scx_idle_cpu_core(cpu);
	if (!core)
		return -EINVAL;

	if (!idle) {
		bmp_clear_bit(cpu, mask_idle_core);
		return scx_idle_set_smt(core, false);
	}

	bmp_set_bit(cpu, mask_idle_core);
	if (!scx_idle_core_is_idle(core))
		return 0;

	/* The SMT mask is an optimization and converges after racing updates. */
	return scx_idle_set_smt(core, true);
}
