#pragma once

struct scx_cpumask {
	u64 *bits;
};

void scx_cpumask_set_cpu(unsigned int, struct scx_cpumask *);
void scx_cpumask_clear_cpu(unsigned int, struct scx_cpumask *);
bool scx_cpumask_test_cpu(unsigned int, struct scx_cpumask *);
bool scx_cpumask_empty(struct scx_cpumask *);
void scx_cpumask_clear(struct scx_cpumask *);
bool scx_cpumask_intersects(struct scx_cpumask *, struct scx_cpumask *);
void scx_cpumask_copy(struct scx_cpumask *, struct scx_cpumask *);
void scx_cpumask_from_bpf(struct scx_cpumask *, struct bpf_cpumask *);
void scx_cpumask_to_bpf(struct bpf_cpumask *, struct scx_cpumask *);
void scx_cpumask_from_cpumask(struct scx_cpumask *, const struct cpumask *);
bool scx_cpumask_subset(struct scx_cpumask *, struct scx_cpumask *);
void scx_cpumask_and(struct scx_cpumask *, struct scx_cpumask *, struct scx_cpumask *);

int scx_cpumask_init(void);
struct scx_cpumask __arena *scx_cpumask_alloc(void);
void scx_cpumask_free(struct scx_cpumask __arena *scxmask);