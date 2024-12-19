#pragma once

#define NR_CPUS (256)

struct scx_cpumask {
	u64 bits[NR_CPUS / 64];
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
void scx_cpumask_from_bpf_arena(struct scx_cpumask *, struct bpf_cpumask *);
void scx_cpumask_to_bpf_arena(struct bpf_cpumask *, struct scx_cpumask *);
void scx_cpumask_from_cpumask_arena(struct scx_cpumask *, const struct cpumask *);
