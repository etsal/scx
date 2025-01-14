#pragma once

void running_update_vtime(struct task_struct *p,
				 struct task_ctx *taskc,
				 dom_ptr domc);
void stopping_update_vtime(struct task_struct *p,
				  struct task_ctx *taskc,
				  dom_ptr domc);
void place_task_dl(struct task_struct *p, struct task_ctx *taskc,
			  u64 enq_flags);
u64 task_compute_dl(struct task_struct *p, struct task_ctx *taskc,
			   u64 enq_flags);
