#include <scx/common.bpf.h>

#include "include/lib/cpumask.h"

/*
 * NOTE: This file deliberately implements only bitmap operations we actively
 * use, to make sure we exercise the library.
 */

__hidden void
scx_cpumask_set_cpu(unsigned int cpu, struct scx_cpumask *mask)
{
	int ind;

	if (!mask)
		return;

	ind = cpu / 64;
	if (ind >= SCX_MASKLEN)
		return;

	mask->bits[ind] |= (1U << (cpu % 64));
}

__hidden void
scx_cpumask_clear_cpu(unsigned int cpu, struct scx_cpumask *mask)
{
	int ind;

	if (!mask)
		return;

	ind = cpu / 64;
	if (ind >= SCX_MASKLEN)
		return;

	mask->bits[ind] &= ~(1U << (cpu % 64));
}

__hidden bool
scx_cpumask_test_cpu(unsigned int cpu, struct scx_cpumask *mask)
{
	int ind;

	if (!mask)
		return false;

	ind = cpu / 64;
	if (ind >= SCX_MASKLEN)
		return false;

	return (mask->bits[ind] & (1U << (cpu % 64))) != 0;
}

__hidden bool
scx_cpumask_empty(struct scx_cpumask *mask)
{
	u64 bits = 0ULL;

	if (!mask)
		return false;

	_Static_assert(sizeof(struct scx_cpumask) == 32, "cpumask should be 32 bytes");
	bits |= mask->bits[0];
	bits |= mask->bits[1];
	bits |= mask->bits[2];
	bits |= mask->bits[3];

	return bits == 0;
}

__hidden void
scx_cpumask_clear(struct scx_cpumask *mask)
{
	if (!mask)
		return;

	mask->bits[0] = 0;
	mask->bits[1] = 0;
	mask->bits[2] = 0;
	mask->bits[3] = 0;
}

__hidden void
scx_cpumask_and(struct scx_cpumask *dst, struct scx_cpumask *mask1, struct scx_cpumask *mask2)
{
	if (!mask1 || !mask2)
		return;

	dst->bits[0] = mask1->bits[0] & mask2->bits[0];
	dst->bits[1] = mask1->bits[1] & mask2->bits[1];
	dst->bits[2] = mask1->bits[2] & mask2->bits[2];
	dst->bits[3] = mask1->bits[3] & mask2->bits[3];
}


bool
scx_cpumask_intersects(struct scx_cpumask *mask1, struct scx_cpumask *mask2)
{
	u64 bits = 0;

	if (!mask1 || !mask2) {
		scx_bpf_error("no mask");
		return false;
	}

	bits |= mask1->bits[0] & mask2->bits[0];
	bits |= mask1->bits[1] & mask2->bits[1];
	bits |= mask1->bits[2] & mask2->bits[2];
	bits |= mask1->bits[3] & mask2->bits[3];

	return bits != 0;
}

bool
scx_cpumask_subset(struct scx_cpumask *mask1, struct scx_cpumask *mask2)
{
	u64 bits = 0;

	if (!mask1 || !mask2)
		return false;

	bits |= mask1->bits[0] & ~mask2->bits[0];
	bits |= mask1->bits[1] & ~mask2->bits[1];
	bits |= mask1->bits[2] & ~mask2->bits[2];
	bits |= mask1->bits[3] & ~mask2->bits[3];

	return bits == 0;
}

__hidden void
scx_cpumask_copy(struct scx_cpumask *dst, struct scx_cpumask *src)
{
	if (!src || !dst)
		return;

	dst->bits[0] = src->bits[0];
	dst->bits[1] = src->bits[1];
	dst->bits[2] = src->bits[2];
	dst->bits[3] = src->bits[3];
}

__hidden void
scx_cpumask_to_bpf(struct bpf_cpumask *bpfmask, struct scx_cpumask *scxmask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_import(cast_mask(bpfmask), &tmp, sizeof(tmp)) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(&scxmask, &tmp);
}

__hidden void
scx_cpumask_from_bpf(struct scx_cpumask *scxmask, struct bpf_cpumask *bpfmask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_export(&tmp, sizeof(tmp), cast_mask(bpfmask)) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(&scxmask, &tmp);
}

__hidden void
scx_cpumask_from_cpumask(struct scx_cpumask *scxmask, const struct cpumask *cpumask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_export(&tmp, sizeof(tmp), cpumask) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(&scxmask, &tmp);
}

/*
 * The register type of the function is practically part of the type system, so
 * for a function we can either pass an arena (map) pointer or a regular pointer, but
 * not both. Doing otherwise causes the verifier to reject the program. The code
 * below is an exact duplicate of the one above.
 */
__hidden void
scx_cpumask_to_bpf_arena(struct bpf_cpumask *bpfmask, struct scx_cpumask *scxmask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_import(cast_mask(bpfmask), &tmp, sizeof(tmp)) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(&scxmask, &tmp);
}

__hidden void
scx_cpumask_from_bpf_arena(struct scx_cpumask *scxmask, struct bpf_cpumask *bpfmask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_export(&tmp, sizeof(tmp), cast_mask(bpfmask)) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(&scxmask, &tmp);
}

__hidden void
scx_cpumask_from_cpumask_arena(struct scx_cpumask *scxmask, const struct cpumask *cpumask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_export(&tmp, sizeof(tmp), cpumask) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(&scxmask, &tmp);
}

