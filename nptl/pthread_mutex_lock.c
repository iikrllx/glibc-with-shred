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

#include <errno.h>
#include "pthreadP.h"
#include <lowlevellock.h>


int
__pthread_mutex_lock (mutex)
     pthread_mutex_t *mutex;
{
  struct pthread *id = THREAD_ID;

  switch (__builtin_expect (mutex->__data.__kind, PTHREAD_MUTEX_TIMED_NP))
    {
      /* Recursive mutex.  */
    case PTHREAD_MUTEX_RECURSIVE_NP:
      /* Check whether we already hold the mutex.  */
      if (mutex->__data.__owner == id)
	{
	  /* Just bump the counter.  */
	  if (__builtin_expect (mutex->__data.__count + 1 == 0, 0))
	    /* Overflow of the counter.  */
	    return EAGAIN;

	  ++mutex->__data.__count;
	}
      else
	{
	  /* We have to get the mutex.  */
	  lll_mutex_lock (mutex->__data.__lock);

	  /* Record the ownership.  */
	  mutex->__data.__owner = id;
	  mutex->__data.__count = 1;
	}
      break;

      /* Error checking mutex.  */
    case PTHREAD_MUTEX_ERRORCHECK_NP:
      /* Check whether we already hold the mutex.  */
      if (mutex->__data.__owner == id)
	return EDEADLK;

      /* FALLTHROUGH */

    default:
      /* Correct code cannot set any other type.  */
    case PTHREAD_MUTEX_TIMED_NP:
    case PTHREAD_MUTEX_ADAPTIVE_NP:
      /* Normal mutex.  */
      lll_mutex_lock (mutex->__data.__lock);
      /* Record the ownership.  */
      mutex->__data.__owner = id;
      break;
    }

  return 0;
}
strong_alias (__pthread_mutex_lock, pthread_mutex_lock)
strong_alias (__pthread_mutex_lock, __pthread_mutex_lock_internal)
