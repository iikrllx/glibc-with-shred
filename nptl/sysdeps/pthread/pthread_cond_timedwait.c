/* Copyright (C) 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Martin Schwidefsky <schwidefsky@de.ibm.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <endian.h>
#include <errno.h>
#include <sysdep.h>
#include <lowlevellock.h>
#include <pthread.h>
#include <pthreadP.h>

#include <shlib-compat.h>


/* Cleanup handler, defined in pthread_cond_wait.c.  */
extern void __condvar_cleanup (void *arg)
     __attribute__ ((visibility ("hidden")));

struct _condvar_cleanup_buffer
{
  int oldtype;
  pthread_cond_t *cond;
  pthread_mutex_t *mutex;
};

int
__pthread_cond_timedwait (cond, mutex, abstime)
     pthread_cond_t *cond;
     pthread_mutex_t *mutex;
     const struct timespec *abstime;
{
  struct _pthread_cleanup_buffer buffer;
  struct _condvar_cleanup_buffer cbuffer;
  int result = 0;

  /* Catch invalid parameters.  */
  if (abstime->tv_nsec >= 1000000000)
    return EINVAL;

  /* Make sure we are along.  */
  lll_mutex_lock (cond->__data.__lock);

  /* Now we can release the mutex.  */
  int err = __pthread_mutex_unlock_internal (mutex);
  if (err)
    {
      lll_mutex_unlock (cond->__data.__lock);
      return err;
    }

  /* We have one new user of the condvar.  */
  ++cond->__data.__total_seq;

  /* Prepare structure passed to cancellation handler.  */
  cbuffer.cond = cond;
  cbuffer.mutex = mutex;

  /* Before we block we enable cancellation.  Therefore we have to
     install a cancellation handler.  */
  __pthread_cleanup_push (&buffer, __condvar_cleanup, &cbuffer);

  /* The current values of the wakeup counter.  The "woken" counter
     must exceed this value.  */
  unsigned long long int val;
  unsigned long long int seq;
  val = seq = cond->__data.__wakeup_seq;

  /* The futex syscall operates on a 32-bit word.  That is fine, we
     just use the low 32 bits of the sequence counter.  */
#if BYTE_ORDER == LITTLE_ENDIAN
  int *futex = ((int *) (&cond->__data.__wakeup_seq));
#elif BYTE_ORDER == BIG_ENDIAN
  int *futex = ((int *) (&cond->__data.__wakeup_seq)) + 1;
#else
# error "No valid byte order"
#endif

  while (1)
    {
      /* Get the current time.  So far we support only one clock.  */
      struct timeval tv;
      (void) gettimeofday (&tv, NULL);

      /* Convert the absolute timeout value to a relative timeout.  */
      struct timespec rt;
      rt.tv_sec = abstime->tv_sec - tv.tv_sec;
      rt.tv_nsec = abstime->tv_nsec - tv.tv_usec * 1000;
      if (rt.tv_nsec < 0)
	{
	  rt.tv_nsec += 1000000000;
	  --rt.tv_sec;
	}
      /* Did we already time out?  */
      if (rt.tv_sec < 0)
	{
	  /* Yep.  Adjust the sequence counter.  */
	  ++cond->__data.__wakeup_seq;

	  /* The error value.  */
	  result = ETIMEDOUT;
	  break;
	}

      /* Prepare to wait.  Release the condvar futex.  */
      lll_mutex_unlock (cond->__data.__lock);

      /* Enable asynchronous cancellation.  Required by the standard.  */
      __pthread_enable_asynccancel_2 (&cbuffer.oldtype);

      /* Wait until woken by signal or broadcast.  Note that we
	 truncate the 'val' value to 32 bits.  */
      err = lll_futex_timed_wait (futex, (unsigned int) val, &rt);

      /* Disable asynchronous cancellation.  */
      __pthread_disable_asynccancel (cbuffer.oldtype);

      /* We are going to look at shared data again, so get the lock.  */
      lll_mutex_lock(cond->__data.__lock);

      /* Check whether we are eligible for wakeup.  */
      val = cond->__data.__wakeup_seq;
      if (cond->__data.__woken_seq >= seq
	  && cond->__data.__woken_seq < val)
	break;

      /* Not woken yet.  Maybe the time expired?  */
      if (err == -ETIMEDOUT)
	{
	  /* Yep.  Adjust the counters.  */
	  ++cond->__data.__wakeup_seq;

	  /* The error value.  */
	  result = ETIMEDOUT;
	  break;
	}
    }

  /* Another thread woken up.  */
  ++cond->__data.__woken_seq;

  /* We are done with the condvar.  */
  lll_mutex_unlock (cond->__data.__lock);

  /* The cancellation handling is back to normal, remove the handler.  */
  __pthread_cleanup_pop (&buffer, 0);

  /* Get the mutex before returning.  */
  err = __pthread_mutex_lock_internal (mutex);

  return err ?: result;
}

versioned_symbol (libpthread, __pthread_cond_timedwait, pthread_cond_timedwait,
		  GLIBC_2_3_2);
