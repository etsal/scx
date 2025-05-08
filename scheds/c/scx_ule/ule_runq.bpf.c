
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.h>
#include <lib/sdt_task.h>

#include "scx_ule.h"
#include "queue.h"


volatile int sched_slice_min = 1;
volatile int sched_slice = 10;

static
void ule_runq_setbit(struct ule_runq *rq, u8 prio)
{
	rq->status |= 1ULL << prio;
}

static
void ule_runq_clrbit(struct ule_runq *rq, u8 prio)
{
	rq->status &= ~(1ULL << prio);
}

static
void ule_runq_add(struct ule_runq *rq, task_ptr taskc, int flags, u8 prio)
{
	struct ule_rqhead *rqh;

	taskc->rqidx = prio;

	ule_runq_setbit(rq, prio);
	rqh = &rq->queues[prio];

	/* XXX Insert on head if dequeued due to preemption. */
	TAILQ_INSERT_TAIL(rqh, taskc, rqptr);
}

static
u8 ule_runq_remove(struct ule_runq *rq, task_ptr taskc, u8 idx)
{
	struct ule_rqhead *rqh;
	u8 prio;

	prio = taskc->prio;
	if (prio >= ULE_NRQ) {
		scx_bpf_error("runqueue index out of bounds");
		return 0;
	}

	rqh = &rq->queues[prio];
	TAILQ_REMOVE(rqh, taskc, rqptr);
	if (TAILQ_EMPTY(rqh)) {
		ule_runq_clrbit(rq, prio);
		if (idx == prio)
			return (prio + 1) % ULE_NRQ;
	}

	/*
	 * Special value: Do not update idx. Function written this
	 * way because BPF does not like input/output arguments.
	 */
	return ULE_NRQ;
}

static
task_ptr ule_runq_steal(struct ule_runq *rq, int cpu, u8 start)
{
	if (rq->status == 0)
		return NULL;

	/*
	 * XXX Iterate through the queues of the rq, for each populated queue
	 * find a task that is both migratable and schedulable and return it.
	 * Skip the first task we find. Start from the queue for priority start,
	 * then loop back if necessary.
	 */

	return NULL;
}

static
void cpu_runq_add(struct cpu_ctx *cpuc, task_ptr taskc, int flags)
{
	u8 prio = taskc->prio;

	/* XXX Only add the load if the task is transferrable. */
	cpuc->load += 1;
	if (prio < PRI_MIN_TIMESHARE) {
		taskc->runq = &cpuc->rq_realtime;
		ule_runq_add(taskc->runq, taskc, flags, prio);
		return;
	}

	taskc->runq = &cpuc->rq_timeshare;

	/*
	 * XXX If we got preempted or got priority boosted, enqueue as fast
	 * as possible. Right now we don't properly mark these states, so
	 * write both code paths and fix the condition below.
	 */
	prio = cpuc->ridx;
	if (0) {
		/*
		 * Effectively this delays the execution of the batch task
		 * by placing it in a further queue the less important the
		 * task.
		 */
		prio = ULE_NRQ * (prio - PRI_MIN_BATCH) / PRI_BATCH_RANGE;
		prio = (prio + cpuc->ridx) / PRI_BATCH_RANGE;

		/*
		 * Do not loop around so much that the thread ends up
		 * heavily prioritized.
		 */
		if (cpuc->idx != cpuc->ridx && prio == cpuc->ridx)
			prio = (u8)(prio - 1) % ULE_NRQ;
	}

	ule_runq_add(taskc->runq, taskc, prio, flags);
}

static
void cpu_runq_rem(struct cpu_ctx *cpuc, task_ptr taskc)
{
	u8 idx;

	cpuc->load -= 1;

	/* Purposely convoluted, see comment in ule_runq_remove. */
	idx = ULE_NRQ;
	if (cpuc->idx != cpuc->ridx)
		idx = ule_runq_remove(taskc->runq, taskc, idx);

	if (idx != ULE_NRQ)
		cpuc->ridx = idx;
}

static
void cpu_load_add(struct cpu_ctx *cpuc, task_ptr taskc)
{
	cpuc->load += 1;
}

static
void cpu_load_rem(struct cpu_ctx *cpuc, task_ptr taskc)
{
	cpuc->load -= 1;
}

static
int cpu_slice(struct cpu_ctx *cpuc)
{
	int load = cpuc->load - 1;

	if (load >= SCHED_SLICE_MIN_DIVISOR)
		return sched_slice_min;

	if (load <= 1)
		return (sched_slice);

	return sched_slice / load;
}
