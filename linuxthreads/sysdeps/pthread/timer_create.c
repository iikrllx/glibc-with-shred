/* Copyright (C) 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Kaz Kylheku <kaz@ashi.footprints.net>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include "posix-timer.h"


/* Create new per-process timer using CLOCK.  */
int
timer_create (clock_id, evp, timerid)
     clockid_t clock_id;
     struct sigevent *evp;
     timer_t *timerid;
{
  int retval = -1;
  struct timer_node *newtimer = NULL;
  struct thread_node *thread = NULL;

  if (clock_id != CLOCK_REALTIME)
    {
      errno = EINVAL;
      return -1;
    }

  pthread_once (&__timer_init_once_control, __timer_init_once);

  if (__timer_init_failed)
    {
      errno = ENOMEM;
      return -1;
    }

  pthread_mutex_lock (&__timer_mutex);

  newtimer = __timer_alloc ();
  if (__builtin_expect (newtimer == NULL, 0))
    {
      errno = EAGAIN;
      goto unlock_bail;
    }

  if (evp != NULL)
    newtimer->event = *evp;
  else
    {
      newtimer->event.sigev_notify = SIGEV_SIGNAL;
      newtimer->event.sigev_signo = SIGALRM;
      newtimer->event.sigev_value.sival_int = timer_ptr2id (newtimer);
      newtimer->event.sigev_notify_function = 0;
    }

  newtimer->event.sigev_notify_attributes = &newtimer->attr;

  switch (__builtin_expect (newtimer->event.sigev_notify, SIGEV_SIGNAL))
    {
    case SIGEV_NONE:
      /* This is a strange choice!  */
      break;

    case SIGEV_SIGNAL:
      /* We have a global thread for delivering timed signals.
	 If it is not running, try to start it up.  */
      if (! __timer_signal_thread.exists)
	{
	  if (__builtin_expect (__timer_thread_start (&__timer_signal_thread),
				1) < 0)
	    {
	      errno = EAGAIN;
	      goto unlock_bail;
            }
        }
      thread = &__timer_signal_thread;
      break;

    case SIGEV_THREAD:
      /* Copy over thread attributes or set up default ones.  */
      if (evp->sigev_notify_attributes)
	newtimer->attr = *(pthread_attr_t *) evp->sigev_notify_attributes;
      else
	pthread_attr_init (&newtimer->attr);

      /* Ensure thread attributes call for deatched thread.  */
      pthread_attr_setdetachstate (&newtimer->attr, PTHREAD_CREATE_DETACHED);

      /* Try to find existing thread having the right attributes.  */
      thread = __timer_thread_find_matching (&newtimer->attr);

      /* If no existing thread has these attributes, try to allocate one.  */
      if (thread == NULL)
	thread = __timer_thread_alloc (&newtimer->attr);

      /* Out of luck; no threads are available.  */
      if (__builtin_expect (thread == NULL, 0))
	{
	  errno = EAGAIN;
	  goto unlock_bail;
	}

      /* If the thread is not running already, try to start it.  */
      if (! thread->exists
	  && __builtin_expect (! __timer_thread_start (thread), 0))
	{
	  errno = EAGAIN;
	  goto unlock_bail;
	}
      break;

    default:
      errno = EINVAL;
      goto unlock_bail;
    }

  newtimer->clock = clock_id;
  newtimer->abstime = 0;
  newtimer->armed = 0;
  newtimer->thread = thread;

  *timerid = timer_ptr2id (newtimer);
  retval = 0;

  if (__builtin_expect (retval, 0) == -1)
    {
    unlock_bail:
      if (thread != NULL)
	__timer_thread_dealloc (thread);
      if (newtimer != NULL)
	__timer_dealloc (newtimer);
    }

  pthread_mutex_unlock (&__timer_mutex);

  return retval;
}
