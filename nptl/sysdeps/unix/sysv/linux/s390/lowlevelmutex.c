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


void
___lll_mutex_lock (futex, newval)
     int *futex;
     int newval;
{
  int oldval;

  do
    {
      lll_futex_wait (futex, newval);
      lll_compare_and_swap (futex, oldval, newval, "lr %2,%1; ahi %2,1");
    }
  while (oldval != 0);

  *futex = 2;
}


int
___lll_mutex_timedlock (futex, abstime, newval)
     int *futex;
     const struct timespec *abstime;
     int newval;
{
  /* Reject invalid timeouts.  */
  if (abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000)
    return EINVAL;

  int oldval;
  do
    {
      /* Get the current time.  */
      struct timeval tv;
      __gettimeofday (&tv, NULL);

      /* Compute relative timeout.  */
      struct timespec rt;
      rt.tv_sec = abstime->tv_sec - tv.tv_sec;
      rt.tv_nsec = abstime->tv_nsec - tv.tv_usec * 1000;
      if (rt.tv_nsec < 0)
	{
	  rt.tv_nsec += 1000000000;
	  --rt.tv_sec;
	}
      /* Already timed out?  */
      if (rt.tv_sec < 0)
	return ETIMEDOUT;

      /* Wait.  */
      int err = lll_futex_timed_wait (futex, newval, &rt);

      /* If timed out return with an appropriate error.  */
      if (err == -ETIMEDOUT)
	return ETIMEDOUT;

      /* XXX oldval in undefined !!! */
      lll_compare_and_swap (futex, oldval, newval, "lr %2,%1; ahi %2,1");
    }
  while (oldval != 0);

  *futex = 2;

  return 0;
}
