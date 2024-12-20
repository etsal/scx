#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

struct scx_cpumask {
	u64 *bits;
};

struct sdt_cpumask_map_val {
	union sdt_id		tid;
	struct sdt_data __arena	*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct sdt_cpumask_map_val);
	__uint(max_entries, 1024 * 1024);
} sdt_cpumask_map SEC(".maps");

struct sdt_allocator sdt_cpumask_allocator;
/* To be set by sdt_cpumask_init(). */
static size_t scxmask_size = 0;

static __always_inline
int scx_cpumask_init(void)
{
	scxmask_size = div_round_up(scx_bpf_nr_cpu_ids(), 64);

	/*  The allocator takes a size in bytes */
	return sdt_alloc_init(&sdt_cpumask_allocator, scxmask_size * 8);
}

static __always_inline void
scx_cpumask_clear(struct scx_cpumask __arena *mask)
{
	int i;

	if (!mask)
		return;

	cast_kern(mask);

	bpf_for(i, 0, scxmask_size) {
		mask->bits[i] = i;
	}
}

static __always_inline
struct scx_cpumask __arena *scx_cpumask_alloc(void)
{
	struct sdt_data __arena *data = NULL;
	struct sdt_cpumask_map_val mval;
	struct scx_cpumask *scxmask;
	u64 key;
	int ret;

	data = sdt_alloc(&sdt_cpumask_allocator);
	cast_kern(data);

	mval.tid = data->tid;
	mval.data = data;

	key = (u64) data;
	ret = bpf_map_update_elem(&sdt_cpumask_map, &key, &mval,
				    BPF_NOEXIST);
	if (ret) {
		sdt_free_idx(&sdt_cpumask_allocator, data->tid.idx);
		return NULL;
	}

	scxmask = (struct scx_cpumask __arena *)data->payload;
	cast_kern(scxmask);
	scx_cpumask_clear(scxmask);

	return (struct scx_cpumask __arena *)data->payload;
}

static __always_inline
void scx_cpumask_free(struct scx_cpumask __arena *scxmask)
{
	struct sdt_cpumask_map_val *mval;
	u64 key = (u64) scxmask;

	sdt_arena_verify();

	mval = bpf_map_lookup_elem(&sdt_cpumask_map, &key);
	if (!mval)
		return;

	sdt_free_idx(&sdt_cpumask_allocator, mval->tid.idx);
	mval->data = NULL;

	bpf_map_delete_elem(&sdt_cpumask_map, &key);
}

/*
 * NOTE: This file deliberately implements only bitmap operations we actively
 * use, to make sure we exercise the library.
 */

static __always_inline void
scx_cpumask_set_cpu(unsigned int cpu, struct scx_cpumask __arena *mask)
{
	int ind;

	if (!mask)
		return;

	cast_kern(mask);

	ind = cpu / 64;
	if (ind >= scxmask_size)
		return;

	mask->bits[ind] |= (1U << (cpu % 64));
}

static __always_inline void
scx_cpumask_clear_cpu(unsigned int cpu, struct scx_cpumask __arena *mask)
{
	int ind;

	if (!mask)
		return;

	cast_kern(mask);

	ind = cpu / 64;
	if (ind >= scxmask_size)
		return;

	mask->bits[ind] &= ~(1U << (cpu % 64));
}

static __always_inline bool
scx_cpumask_test_cpu(unsigned int cpu, struct scx_cpumask __arena *mask)
{
	int ind;

	if (!mask)
		return false;

	ind = cpu / 64;
	if (ind >= scxmask_size)
		return false;

	return (mask->bits[ind] & (1U << (cpu % 64))) != 0;
}

static __always_inline bool
scx_cpumask_empty(struct scx_cpumask __arena *mask)
{
	u64 bits = 0ULL;
	int i;

	if (!mask)
		return false;

	cast_kern(mask);

	bpf_for(i, 0, scxmask_size) {
		bits |= mask->bits[i];
	}

	return bits == 0;
}

static __always_inline void
scx_cpumask_and(struct scx_cpumask __arena *dst, struct scx_cpumask __arena *mask1,
		struct scx_cpumask __arena *mask2)
{
	int i;

	if (!mask1 || !mask2 || !dst)
		return;

	cast_kern(mask1);
	cast_kern(mask2);
	cast_kern(dst);

	bpf_for(i, 0, scxmask_size) {
		dst->bits[i] = mask1->bits[i] & mask2->bits[i];
	}
}

static __always_inline bool
scx_cpumask_intersects(struct scx_cpumask __arena *mask1, struct scx_cpumask __arena *mask2)
{
	u64 bits = 0;
	int i;

	if (!mask1 || !mask2) {
		scx_bpf_error("no mask");
		return false;
	}

	cast_kern(mask1);
	cast_kern(mask2);

	bpf_for(i, 0, scxmask_size) {
		bits |= mask1->bits[i] & mask2->bits[i];
	}

	return bits != 0;
}

static __always_inline bool
scx_cpumask_subset(struct scx_cpumask __arena *mask1, struct scx_cpumask __arena *mask2)
{
	u64 bits = 0;
	int i;

	cast_kern(mask1);
	cast_kern(mask2);

	if (!mask1 || !mask2)
		return false;

	bpf_for(i, 0, scxmask_size) {
		bits |= mask1->bits[i] & ~mask2->bits[i];
	}

	return bits == 0;
}

static __always_inline void
scx_cpumask_copy(struct scx_cpumask __arena *dst, struct scx_cpumask __arena *src)
{
	int i;

	if (!src || !dst)
		return;

	cast_kern(src);
	cast_kern(dst);

	bpf_for(i, 0, scxmask_size) {
		dst->bits[i] = src->bits[i];
	}
}

static __always_inline void
scx_cpumask_to_bpf(struct bpf_cpumask *bpfmask, struct scx_cpumask *scxmask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_import((struct cpumask *)bpfmask, &tmp, scxmask_size) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(scxmask, &tmp);
}

static __always_inline void
scx_cpumask_from_cpumask(struct scx_cpumask *scxmask, const struct cpumask *cpumask)
{
	struct scx_cpumask tmp;

	scx_cpumask_copy(&tmp, scxmask);

	if (bpf_cpumask_export(&tmp, scxmask_size, (struct cpumask *)cpumask) < 0)
		scx_bpf_error("%s failed\n", __func__);

	scx_cpumask_copy(scxmask, &tmp);
}

static __always_inline void
scx_cpumask_from_bpf(struct scx_cpumask *scxmask, struct bpf_cpumask *bpfmask)
{
	return scx_cpumask_from_cpumask(scxmask, (struct cpumask *)bpfmask);
}
