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

#include <errno.h>
#include <sysdep.h>
#include <lowlevellock.h>
#include <pthread.h>
#include <pthreadP.h>


/* Acquire read lock for RWLOCK.  */
int
__pthread_rwlock_rdlock (rwlock)
     pthread_rwlock_t *rwlock;
{
  int result = 0;

  /* Make sure we are along.  */
  lll_mutex_lock (rwlock->__data.__lock);

  while (1)
    {
      /* Get the rwlock if there is no writer...  */
      if (rwlock->__data.__writer == 0
	  /* ...and if either no writer is waiting or we prefer readers.  */
	  && (!rwlock->__data.__nr_writers_queued
	      || rwlock->__data.__flags == 0))
	{
	  /* Increment the reader counter.  Avoid overflow.  */
	  if (__builtin_expect (++rwlock->__data.__nr_readers == 0, 0))
	    {
	      /* Overflow on number of readers.	 */
	      --rwlock->__data.__nr_readers;
	      result = EAGAIN;
	    }

	  break;
	}

      /* Make sure we are not holding the rwlock as a writer.  This is
	 a deadlock situation we recognize and report.  */
      if (rwlock->__data.__writer != 0
	  && __builtin_expect (rwlock->__data.__writer
			       == (pthread_t) THREAD_SELF, 0))
	{
	  result = EDEADLK;
	  break;
	}

      /* Remember that we are a reader.  */
      if (__builtin_expect (++rwlock->__data.__nr_readers_queued == 0, 0))
	{
	  /* Overflow on number of queued readers.  */
	  --rwlock->__data.__nr_readers_queued;
	  result = EAGAIN;
	  break;
	}

      /* Free the lock.  */
      lll_mutex_unlock (rwlock->__data.__lock);

      /* Wait for the writer to finish.  */
      lll_futex_wait (&rwlock->__data.__readers_wakeup, 0);

      /* Get the lock.  */
      lll_mutex_lock (rwlock->__data.__lock);

      /* To start over again, remove the thread from the reader list.  */
      if (--rwlock->__data.__nr_readers_queued == 0)
	rwlock->__data.__readers_wakeup = 0;
    }

  /* We are done, free the lock.  */
  lll_mutex_unlock (rwlock->__data.__lock);

  return result;
}

weak_alias (__pthread_rwlock_rdlock, pthread_rwlock_rdlock)
strong_alias (__pthread_rwlock_rdlock, __pthread_rwlock_rdlock_internal)
