/* Copyright (C) 2002, 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <atomic.h>
#include <ldsodefs.h>
#include <tls.h>

#include "kernel-features.h"


#define CLONE_SIGNAL    	(CLONE_SIGHAND | CLONE_THREAD)

/* Unless otherwise specified, the thread "register" is going to be
   initialized with a pointer to the TCB.  */
#ifndef TLS_VALUE
# define TLS_VALUE pd
#endif

#ifndef ARCH_CLONE
# define ARCH_CLONE __clone
#endif


#ifndef TLS_MULTIPLE_THREADS_IN_TCB
/* Variable set to a nonzero value if more than one thread runs or ran.  */
int __pthread_multiple_threads attribute_hidden;
/* Pointer to the corresponding variable in libc.  */
int *__libc_multiple_threads_ptr attribute_hidden;
#endif


static int
do_clone (struct pthread *pd, const struct pthread_attr *attr,
	  int clone_flags, int (*fct) (void *), STACK_VARIABLES_PARMS)
{
#ifdef PREPARE_CREATE
  PREPARE_CREATE;
#endif

  /* Lame old kernels do not have CLONE_STOPPED support.  For those do
     not pass the flag, not instead use the futex method.  */
#ifndef __ASSUME_CLONE_STOPPED
# define final_clone_flags clone_flags & ~CLONE_STOPPED
  if (clone_flags & CLONE_STOPPED)
    /* We Make sure the thread does not run far by forcing it to get a
       lock.  We lock it here too so that the new thread cannot continue
       until we tell it to.  */
    lll_lock (pd->lock);
#else
# define final_clone_flags clone_flags
#endif

  if (ARCH_CLONE (fct, STACK_VARIABLES_ARGS, final_clone_flags,
		  pd, &pd->tid, TLS_VALUE, &pd->tid) == -1)
    /* Failed.  */
    return errno;

  /* Now we have the possibility to set scheduling parameters etc.  */
  if (__builtin_expect ((clone_flags & CLONE_STOPPED) != 0, 0))
    {
      INTERNAL_SYSCALL_DECL (err);
      int res = 0;

      /* Set the affinity mask if necessary.  */
      if (attr->cpuset != NULL)
	{
	  res = INTERNAL_SYSCALL (sched_setaffinity, err, 3, pd->tid,
				  sizeof (cpu_set_t), attr->cpuset);

	  if (__builtin_expect (INTERNAL_SYSCALL_ERROR_P (res, err), 0))
	    goto err_out;
	}

      /* Set the scheduling parameters.  */
      if ((attr->flags & ATTR_FLAG_NOTINHERITSCHED) != 0)
	{
	  res = INTERNAL_SYSCALL (sched_setscheduler, err, 3, pd->tid,
				  pd->schedpolicy, &pd->schedparam);

	  if (__builtin_expect (INTERNAL_SYSCALL_ERROR_P (res, err), 0))
	    goto err_out;
	}

#ifdef __ASSUME_CLONE_STOPPED
      /* Now start the thread for real.  */
      res = INTERNAL_SYSCALL (tkill, err, 2, pd->tid, SIGCONT);
#endif

      /* If something went wrong, kill the thread.  */
      if (__builtin_expect (INTERNAL_SYSCALL_ERROR_P (res, err), 0))
	{
	  /* The operation failed.  We have to kill the thread.  First
             send it the cancellation signal.  */
	  INTERNAL_SYSCALL_DECL (err2);
	err_out:
	  (void) INTERNAL_SYSCALL (tkill, err2, 2, pd->tid, SIGCANCEL);

#ifdef __ASSUME_CLONE_STOPPED
	  /* Then wake it up so that the signal can be processed.  */
	  (void) INTERNAL_SYSCALL (tkill, err2, 2, pd->tid, SIGCONT);
#endif

	  return INTERNAL_SYSCALL_ERRNO (res, err);
	}
    }

  /* We now have for sure more than one thread.  The main thread might
     not yet have the flag set.  No need to set the global variable
     again if this is what we use.  */
  THREAD_SETMEM (THREAD_SELF, header.multiple_threads, 1);

  return 0;
}


static int
create_thread (struct pthread *pd, const struct pthread_attr *attr,
	       STACK_VARIABLES_PARMS)
{
#ifdef TLS_TCB_AT_TP
  assert (pd->header.tcb != NULL);
#endif

  /* We rely heavily on various flags the CLONE function understands:

     CLONE_VM, CLONE_FS, CLONE_FILES
	These flags select semantics with shared address space and
	file descriptors according to what POSIX requires.

     CLONE_SIGNAL
	This flag selects the POSIX signal semantics.

     CLONE_SETTLS
	The sixth parameter to CLONE determines the TLS area for the
	new thread.

     CLONE_PARENT_SETTID
	The kernels writes the thread ID of the newly created thread
	into the location pointed to by the fifth parameters to CLONE.

	Note that it would be semantically equivalent to use
	CLONE_CHILD_SETTID but it is be more expensive in the kernel.

     CLONE_CHILD_CLEARTID
	The kernels clears the thread ID of a thread that has called
	sys_exit() in the location pointed to by the seventh parameter
	to CLONE.

     CLONE_DETACHED
	No signal is generated if the thread exists and it is
	automatically reaped.

     The termination signal is chosen to be zero which means no signal
     is sent.  */
  int clone_flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGNAL
		     | CLONE_SETTLS | CLONE_PARENT_SETTID
		     | CLONE_CHILD_CLEARTID | CLONE_DETACHED | CLONE_SYSVSEM
		     | 0);

  /* If the newly created threads has to be started stopped since we
     have to set the scheduling parameters or set the affinity we set
     the CLONE_STOPPED flag.  */
  if (attr != NULL && (attr->cpuset != NULL
		       || (attr->flags & ATTR_FLAG_NOTINHERITSCHED) != 0))
    clone_flags |= CLONE_STOPPED;

  if (__builtin_expect (THREAD_GETMEM (THREAD_SELF, report_events), 0))
    {
      /* The parent thread is supposed to report events.  Check whether
	 the TD_CREATE event is needed, too.  */
      const int _idx = __td_eventword (TD_CREATE);
      const uint32_t _mask = __td_eventmask (TD_CREATE);

      if ((_mask & (__nptl_threads_events.event_bits[_idx]
		    | pd->eventbuf.eventmask.event_bits[_idx])) != 0)
	{
	  /* Create the thread.  We always create the thread stopped
	     so that it does not get far before we tell the debugger.  */
	  int res = do_clone (pd, attr, clone_flags | CLONE_STOPPED,
			      start_thread, STACK_VARIABLES_ARGS);
	  if (res == 0)
	    {
	      /* Now fill in the information about the new thread in
		 the newly created thread's data structure.  We cannot let
		 the new thread do this since we don't know whether it was
		 already scheduled when we send the event.  */
	      pd->eventbuf.eventnum = TD_CREATE;
	      pd->eventbuf.eventdata = pd;

	      /* Enqueue the descriptor.  */
	      do
		pd->nextevent = __nptl_last_event;
	      while (atomic_compare_and_exchange_bool_acq (&__nptl_last_event,
							   pd, pd->nextevent)
		     != 0);

	      /* Now call the function which signals the event.  */
	      __nptl_create_event ();

	      /* And finally restart the new thread.  */
	      lll_unlock (pd->lock);
	    }

	  return res;
	}
    }

#ifdef NEED_DL_SYSINFO
  assert (THREAD_GETMEM (THREAD_SELF, header.sysinfo) == pd->header.sysinfo);
#endif

  /* Actually create the thread.  */
  int res = do_clone (pd, attr, clone_flags, start_thread,
		      STACK_VARIABLES_ARGS);

#ifndef __ASSUME_CLONE_STOPPED
  if (res == 0 && (clone_flags & CLONE_STOPPED))
    {
      /* And finally restart the new thread.  */
      lll_unlock (pd->lock);
    }
#endif

  return res;
}
