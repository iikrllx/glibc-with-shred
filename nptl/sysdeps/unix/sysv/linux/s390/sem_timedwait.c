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
#include <internaltypes.h>
#include <semaphore.h>

#include <pthreadP.h>
#include <shlib-compat.h>


int
sem_timedwait (sem, abstime)
     sem_t *sem;
     const struct timespec *abstime;
{
  /* First check for cancellation.  */
  CANCELLATION_P (THREAD_SELF);

  int *futex = (int *) sem;
  int oldval;
  int newval;
  int err;

  do
    {
      /* Atomically decrement semaphore counter if it is > 0.  */
      lll_compare_and_swap (futex, oldval, newval,
			    "ltr %2,%1; jnp 1f; ahi %2,-1");
      /* oldval != newval if the semaphore count has been decremented.	*/
      if (oldval != newval)
	return 0;

      /* Check for invalid timeout values.  */
      if (abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000)
	{
	  __set_errno (EINVAL);
	  return -1;
	}

      /* Get the current time.  */
      struct timeval tv;
      (void) __gettimeofday (&tv, NULL);

      /* Compute the relative timeout.  */
      struct timespec rt;
      rt.tv_sec = abstime->tv_sec - tv.tv_sec;
      rt.tv_nsec = abstime->tv_nsec - tv.tv_usec * 1000;
      if (rt.tv_nsec < 0)
	{
	  rt.tv_nsec += 1000000000;
	  --rt.tv_sec;
	}
      /* Already timed out.  */
      if (rt.tv_sec < 0)
	{
	  __set_errno (ETIMEDOUT);
	  return -1;
	}

      /* Enable asynchronous cancellation.  Required by the standard.  */
      int oldtype = __pthread_enable_asynccancel ();

      /* Do wait.  */
      err = lll_futex_timed_wait (futex, 0, &rt);

      /* Disable asynchronous cancellation.  */
      __pthread_disable_asynccancel (oldtype);

      /* Returned after timing out?  */
      if (err == -ETIMEDOUT)
	{
	  __set_errno (ETIMEDOUT);
	  return -1;
	}
    }
  while (err == 0 || err == -EWOULDBLOCK)

    __set_errno (-err);
  return -1;
}
