/* Copyright (C) 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <sysdep.h>
#include <kernel-features.h>
#include <nptl/pthreadP.h>
#include "kernel-posix-timers.h"


#ifdef __NR_timer_create
/* Helper thread to call the user-provided function.  */
static void *
timer_sigev_thread (void *arg)
{
  struct timer *tk = (struct timer *) arg;

  /* Call the user-provided function.  */
  tk->thrfunc (tk->sival);

  return NULL;
}


/* Helper function to support starting threads for SIGEV_THREAD.  */
static void *
timer_helper_thread (void *arg)
{
  /* Block all signals.  We will only wait for the signal the kernel
     will send.  */
  sigset_t ss;
  sigemptyset (&ss);
  sigaddset (&ss, SIGTIMER);

  /* Endless loop of waiting for signals.  The loop is only ended when
     the thread is canceled.  */
  while (1)
    {
      siginfo_t si;

      if (sigwaitinfo (&ss, &si) > 0 && si.si_code == SI_TIMER)
	{

	  struct timer *tk = (struct timer *) si.si_ptr;

	  /* That the signal we are waiting for.  */
	  pthread_t th;
	  (void) pthread_create (&th, &tk->attr, timer_sigev_thread, tk);
	}
    }
}


/* Control variable for helper thread creation.  */
pthread_once_t __helper_once attribute_hidden;


/* TID of the helper thread.  */
pid_t __helper_tid attribute_hidden;


/* Reset variables so that after a fork a new helper thread gets started.  */
static void
reset_helper_control (void)
{
  __helper_once = PTHREAD_ONCE_INIT;
  __helper_tid = 0;
}


void
attribute_hidden
__start_helper_thread (void)
{
  /* The helper thread needs only very little resources
     and should go away automatically when canceled.  */
  pthread_attr_t attr;
  (void) pthread_attr_init (&attr);
  (void) pthread_attr_setstacksize (&attr, PTHREAD_STACK_MIN);

  /* Create the helper thread for this timer.  */
  pthread_t th;
  int res = pthread_create (&th, &attr, timer_helper_thread, NULL);
  if (res == 0)
    /* We managed to start the helper thread.  */
    __helper_tid = ((struct pthread *) th)->tid;

  /* No need for the attribute anymore.  */
  (void) pthread_attr_destroy (&attr);

  /* We have to make sure that after fork()ing a new helper thread can
     be created.  */
  pthread_atfork (NULL, NULL, reset_helper_control);
}
#endif

#ifndef __ASSUME_POSIX_TIMERS
# include <nptl/sysdeps/pthread/timer_routines.c>
#endif
