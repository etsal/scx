#pragma once
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * FreeBSD-style tail queues, used to generate runqueues. Code adapted from
 * FreeBSD's sys/sys/queue.h.
 */

/*
 * Tail queue declarations.
 * WARNING: The type has to be a typedef'ed arena pointer type.
 */
#define	TAILQ_HEAD(name, type)						\
struct name {								\
	type tqh_first;	/* first element */			\
	type __arena *tqh_last; /* addr of last next element */		\
}

#define	TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }

#define	TAILQ_ENTRY(type)						\
struct {								\
	type tqe_next;	/* next element */			\
	type __arena *tqe_prev;	/* address of previous next element */	\
}

#ifdef DEBUG
#define	QMD_SAVELINK(name, link)	void **name = (void *)&(link)
#define	TRASHIT(x)		do {(x) = (void *)-1;} while (0)
#define	QMD_IS_TRASHED(x)	((x) == (void *)(intptr_t)-1)

/*
 * QMD_TAILQ_CHECK_HEAD(TAILQ_HEAD *head, TAILQ_ENTRY NAME)
 *
 * If the tailq is non-empty, validates that the first element of the tailq
 * points back at 'head.'
 */
#define	QMD_TAILQ_CHECK_HEAD(head, field) do {				\
	if (!TAILQ_EMPTY(head) &&					\
	    TAILQ_FIRST((head))->field.tqe_prev !=			\
	     &TAILQ_FIRST((head)))					\
		scx_bpf_error("Bad tailq head first->prev != head");	\
} while (0)

/*
 * QMD_TAILQ_CHECK_TAIL(TAILQ_HEAD *head, TAILQ_ENTRY NAME)
 *
 * Validates that the tail of the tailq is a pointer to pointer to NULL.
 */
#define	QMD_TAILQ_CHECK_TAIL(head, field) do {				\
	if (*(head)->tqh_last != NULL)					\
		scx_bpf_error("Bad tailq NEXT(->tqh_last) != NULL");	\
} while (0)

/*
 * QMD_TAILQ_CHECK_NEXT(TYPE *elm, TAILQ_ENTRY NAME)
 *
 * If an element follows 'elm' in the tailq, validates that the next element
 * points back at 'elm.'
 */
#define	QMD_TAILQ_CHECK_NEXT(elm, field) do {				\
	if (TAILQ_NEXT((elm), field) != NULL &&				\
	    TAILQ_NEXT((elm), field)->field.tqe_prev !=			\
	     &((elm)->field.tqe_next))					\
		scx_bpf_error("Bad link elm next->prev != elm");	\
} while (0)

/*
 * QMD_TAILQ_CHECK_PREV(TYPE *elm, TAILQ_ENTRY NAME)
 *
 * Validates that the previous element (or head of the tailq) points to 'elm.'
 */
#define	QMD_TAILQ_CHECK_PREV(elm, field) do {				\
	if (*(elm)->field.tqe_prev != (elm))				\
		scx_bpf_error("Bad link elm prev->next != elm");	\
} while (0)
#else
#define	QMD_SAVELINK(name, link)
#define	TRASHIT(x)
#define	QMD_IS_TRASHED(x)	0
#define	QMD_TAILQ_CHECK_HEAD(head, field)
#define	QMD_TAILQ_CHECK_TAIL(head, headname)
#define	QMD_TAILQ_CHECK_NEXT(elm, field)
#define	QMD_TAILQ_CHECK_PREV(elm, field)
#endif /* DEBUG */

#define	TAILQ_CONCAT(head1, head2, field) do {				\
	if (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} while (0)

#define	TAILQ_EMPTY(head)	((head)->tqh_first == NULL)

#define	TAILQ_EMPTY_ATOMIC(head)					\
	(atomic_load_ptr(&(head)->tqh_first) == NULL)

#define	TAILQ_FIRST(head)	((head)->tqh_first)

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) ? (var) : TAILQ_FIRST((head)));		\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	TAILQ_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) ? (var) : TAILQ_FIRST((head)));		\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var);							\
	    (var) = TAILQ_PREV((var), headname, field))

#define	TAILQ_FOREACH_REVERSE_FROM(var, head, headname, field)		\
	for ((var) = ((var) ? (var) : TAILQ_LAST((head), headname));	\
	    (var);							\
	    (var) = TAILQ_PREV((var), headname, field))

#define	TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);	\
	    (var) = (tvar))

#define	TAILQ_FOREACH_REVERSE_FROM_SAFE(var, head, headname, field, tvar)\
	for ((var) = ((var) ? (var) : TAILQ_LAST((head), headname));	\
	    (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);	\
	    (var) = (tvar))

#define	TAILQ_INIT(head) do {						\
	TAILQ_FIRST((head)) = NULL;					\
	(head)->tqh_last = &TAILQ_FIRST((head));			\
} while (0)

#define	TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	QMD_TAILQ_CHECK_NEXT(listelm, field);				\
	if ((TAILQ_NEXT((elm), field) = TAILQ_NEXT((listelm), field)) != NULL)\
		TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    &TAILQ_NEXT((elm), field);				\
	else {								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	}								\
	TAILQ_NEXT((listelm), field) = (elm);				\
	(elm)->field.tqe_prev = &TAILQ_NEXT((listelm), field);		\
} while (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	QMD_TAILQ_CHECK_PREV(listelm, field);				\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	TAILQ_NEXT((elm), field) = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);		\
} while (0)

#define	TAILQ_INSERT_HEAD(head, elm, field) do {			\
	QMD_TAILQ_CHECK_HEAD(head, field);				\
	if ((TAILQ_NEXT((elm), field) = TAILQ_FIRST((head))) != NULL)	\
		TAILQ_FIRST((head))->field.tqe_prev =			\
		    &TAILQ_NEXT((elm), field);				\
	else								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	TAILQ_FIRST((head)) = (elm);					\
	(elm)->field.tqe_prev = &TAILQ_FIRST((head));			\
} while (0)

#define	TAILQ_INSERT_TAIL(head, elm, field) do {			\
	QMD_TAILQ_CHECK_TAIL(head, field);				\
	TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &TAILQ_NEXT((elm), field);			\
} while (0)

#define	TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

/*
 * The FAST function is fast in that it causes no data access other
 * then the access to the head. The standard LAST function above
 * will cause a data access of both the element you want and
 * the previous element. FAST is very useful for instances when
 * you may want to prefetch the last data element.
 */
#define	TAILQ_LAST_FAST(head, type, field)				\
    (TAILQ_EMPTY(head) ? NULL : __containerof((head)->tqh_last, QUEUE_TYPEOF(type), field.tqe_next))

#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define	TAILQ_PREV_FAST(elm, head, type, field)				\
    ((elm)->field.tqe_prev == &(head)->tqh_first ? NULL :		\
     __containerof((elm)->field.tqe_prev, QUEUE_TYPEOF(type), field.tqe_next))

#define TAILQ_REMOVE_HEAD(head, field)					\
	TAILQ_REMOVE(head, TAILQ_FIRST(head), field)

#define	TAILQ_REMOVE(head, elm, field) do {				\
	QMD_TAILQ_CHECK_NEXT(elm, field);				\
	QMD_TAILQ_CHECK_PREV(elm, field);				\
	if ((TAILQ_NEXT((elm), field)) != NULL)				\
		TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    (elm)->field.tqe_prev;				\
	else {								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	}								\
	*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);		\
	TRASHIT(*oldnext);						\
	TRASHIT(*oldprev);						\
} while (0)

#define TAILQ_REMOVE_HEAD(head, field)					\
	TAILQ_REMOVE(head, TAILQ_FIRST(head), field)
