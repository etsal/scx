
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.h>
#include <lib/sdt_task.h>

#include "scx_ule.h"
#include "queue.h"

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

__weak
void ule_runq_add(struct ule_runq *rq, task_ptr taskc, int flags, u8 prio)
{
	struct ule_rqhead *rqh;

	taskc->rqidx = prio;

	ule_runq_setbit(rq, prio);
	rqh = &rq->queues[prio];

	/* XXX Insert on head if dequeued due to preemption. */
	TAILQ_INSERT_TAIL(rqh, taskc, runq);
}

__weak
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
	TAILQ_REMOVE(rqh, taskc, runq);
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

__weak
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
