/* Linuxthreads - a simple clone()-based implementation of Posix        */
/* threads for Linux.                                                   */
/* Copyright (C) 1996 Xavier Leroy (Xavier.Leroy@inria.fr)              */
/*                                                                      */
/* This program is free software; you can redistribute it and/or        */
/* modify it under the terms of the GNU Library General Public License  */
/* as published by the Free Software Foundation; either version 2       */
/* of the License, or (at your option) any later version.               */
/*                                                                      */
/* This program is distributed in the hope that it will be useful,      */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU Library General Public License for more details.                 */

#ifndef _DESCR_H
#define _DESCR_H	1

#define __need_res_state
#include <resolv.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/types.h>
#include <hp-timing.h>
#include <bits/libc-tsd.h> /* for _LIBC_TSD_KEY_N */


/* The type of thread descriptors */
typedef struct _pthread_descr_struct *pthread_descr;


/* Some more includes.  */
#include <pt-machine.h>
#include <linuxthreads_db/thread_dbP.h>


/* Arguments passed to thread creation routine */
struct pthread_start_args {
  void *(*start_routine)(void *); /* function to run */
  void *arg;                      /* its argument */
  sigset_t mask;                  /* initial signal mask for thread */
  int schedpolicy;                /* initial scheduling policy (if any) */
  struct sched_param schedparam;  /* initial scheduling parameters (if any) */
};


/* Callback interface for removing the thread from waiting on an
   object if it is cancelled while waiting or about to wait.
   This hold a pointer to the object, and a pointer to a function
   which ``extricates'' the thread from its enqueued state.
   The function takes two arguments: pointer to the wait object,
   and a pointer to the thread. It returns 1 if an extrication
   actually occured, and hence the thread must also be signalled.
   It returns 0 if the thread had already been extricated. */
typedef struct _pthread_extricate_struct {
    void *pu_object;
    int (*pu_extricate_func)(void *, pthread_descr);
} pthread_extricate_if;


/* Atomic counter made possible by compare_and_swap */
struct pthread_atomic {
  long p_count;
  int p_spinlock;
};


/* Context info for read write locks. The pthread_rwlock_info structure
   is information about a lock that has been read-locked by the thread
   in whose list this structure appears. The pthread_rwlock_context
   is embedded in the thread context and contains a pointer to the
   head of the list of lock info structures, as well as a count of
   read locks that are untracked, because no info structure could be
   allocated for them. */
struct _pthread_rwlock_t;
typedef struct _pthread_rwlock_info {
  struct _pthread_rwlock_info *pr_next;
  struct _pthread_rwlock_t *pr_lock;
  int pr_lock_count;
} pthread_readlock_info;


/* We keep thread specific data in a special data structure, a two-level
   array.  The top-level array contains pointers to dynamically allocated
   arrays of a certain number of data pointers.  So we can implement a
   sparse array.  Each dynamic second-level array has
	PTHREAD_KEY_2NDLEVEL_SIZE
   entries.  This value shouldn't be too large.  */
#define PTHREAD_KEY_2NDLEVEL_SIZE	32

/* We need to address PTHREAD_KEYS_MAX key with PTHREAD_KEY_2NDLEVEL_SIZE
   keys in each subarray.  */
#define PTHREAD_KEY_1STLEVEL_SIZE \
  ((PTHREAD_KEYS_MAX + PTHREAD_KEY_2NDLEVEL_SIZE - 1) \
   / PTHREAD_KEY_2NDLEVEL_SIZE)


union dtv;


struct _pthread_descr_struct {
  /* XXX Remove this union for IA-64 style TLS module */
  union {
    struct {
      pthread_descr self;	/* Pointer to this structure */
      union dtv *dtvp;
    } data;
    void *__padding[16];
  } p_header;
  pthread_descr p_nextlive, p_prevlive;
                                /* Double chaining of active threads */
  pthread_descr p_nextwaiting;  /* Next element in the queue holding the thr */
  pthread_descr p_nextlock;	/* can be on a queue and waiting on a lock */
  pthread_t p_tid;              /* Thread identifier */
  int p_pid;                    /* PID of Unix process */
  int p_priority;               /* Thread priority (== 0 if not realtime) */
  struct _pthread_fastlock * p_lock; /* Spinlock for synchronized accesses */
  int p_signal;                 /* last signal received */
  sigjmp_buf * p_signal_jmp;    /* where to siglongjmp on a signal or NULL */
  sigjmp_buf * p_cancel_jmp;    /* where to siglongjmp on a cancel or NULL */
  char p_terminated;            /* true if terminated e.g. by pthread_exit */
  char p_detached;              /* true if detached */
  char p_exited;                /* true if the assoc. process terminated */
  void * p_retval;              /* placeholder for return value */
  int p_retcode;                /* placeholder for return code */
  pthread_descr p_joining;      /* thread joining on that thread or NULL */
  struct _pthread_cleanup_buffer * p_cleanup; /* cleanup functions */
  char p_cancelstate;           /* cancellation state */
  char p_canceltype;            /* cancellation type (deferred/async) */
  char p_canceled;              /* cancellation request pending */
  int * p_errnop;               /* pointer to used errno variable */
  int p_errno;                  /* error returned by last system call */
  int * p_h_errnop;             /* pointer to used h_errno variable */
  int p_h_errno;                /* error returned by last netdb function */
  char * p_in_sighandler;       /* stack address of sighandler, or NULL */
  char p_sigwaiting;            /* true if a sigwait() is in progress */
  struct pthread_start_args p_start_args; /* arguments for thread creation */
  void ** p_specific[PTHREAD_KEY_1STLEVEL_SIZE]; /* thread-specific data */
  void * p_libc_specific[_LIBC_TSD_KEY_N]; /* thread-specific data for libc */
  int p_userstack;		/* nonzero if the user provided the stack */
  void *p_guardaddr;		/* address of guard area or NULL */
  size_t p_guardsize;		/* size of guard area */
  int p_nr;                     /* Index of descriptor in __pthread_handles */
  int p_report_events;		/* Nonzero if events must be reported.  */
  td_eventbuf_t p_eventbuf;     /* Data for event.  */
  struct pthread_atomic p_resume_count; /* number of times restart() was
					   called on thread */
  char p_woken_by_cancel;       /* cancellation performed wakeup */
  char p_condvar_avail;		/* flag if conditional variable became avail */
  char p_sem_avail;             /* flag if semaphore became available */
  pthread_extricate_if *p_extricate; /* See above */
  pthread_readlock_info *p_readlock_list;  /* List of readlock info structs */
  pthread_readlock_info *p_readlock_free;  /* Free list of structs */
  int p_untracked_readlock_count;	/* Readlocks not tracked by list */
  struct __res_state *p_resp;	/* Pointer to resolver state */
  struct __res_state p_res;	/* per-thread resolver state */
  int p_inheritsched;           /* copied from the thread attribute */
#if HP_TIMING_AVAIL
  hp_timing_t p_cpuclock_offset; /* Initial CPU clock for thread.  */
#endif
  /* New elements must be added at the end.  */
} __attribute__ ((aligned(32))); /* We need to align the structure so that
				    doubles are aligned properly.  This is 8
				    bytes on MIPS and 16 bytes on MIPS64.
				    32 bytes might give better cache
				    utilization.  */

#endif	/* descr.h */
