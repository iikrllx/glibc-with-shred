/* Copyright (C) 2002 Free Software Foundation, Inc.
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
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>


static int kind[] =
  {
    PTHREAD_RWLOCK_PREFER_READER_NP,
    PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP,
    PTHREAD_RWLOCK_PREFER_WRITER_NP,
  };


static void *
tf (void *arg)
{
  pthread_rwlock_t *r = arg;

  /* Timeout: 0.3 secs.  */
  struct timeval tv;
  (void) gettimeofday (&tv, NULL);

  struct timespec ts;
  TIMEVAL_TO_TIMESPEC (&tv, &ts);
  ts.tv_nsec += 300000000;
  if (ts.tv_nsec >= 1000000000)
    {
      ts.tv_nsec -= 1000000000;
      ++ts.tv_sec;
    }

  int err = pthread_rwlock_timedrdlock (r, &ts);
  if (err == 0)
    {
      puts ("rwlock_timedrdlock returned");
      pthread_exit ((void *) 1l);
    }

  if (err != ETIMEDOUT)
    {
      printf ("err = %s (%d), expected %s (%d)\n",
	      strerror (err), err, strerror (ETIMEDOUT), ETIMEDOUT);
      pthread_exit ((void *) 1l);
    }

  struct timeval tv2;
  (void) gettimeofday (&tv2, NULL);

  timersub (&tv2, &tv, &tv);

  if (tv.tv_usec < 200000)
    {
      puts ("timeout too short");
      pthread_exit ((void *) 1l);
    }

  return NULL;
}


static int
do_test (void)
{
  int cnt;
  for (cnt = 0; cnt < sizeof (kind) / sizeof (kind[0]); ++cnt)
    {
      pthread_rwlock_t r;
      pthread_rwlockattr_t a;

      if (pthread_rwlockattr_init (&a) != 0)
	{
	  printf ("round %d: rwlockattr_t failed\n", cnt);
	  exit (1);
	}

      if (pthread_rwlockattr_setkind_np (&a, kind[cnt]) != 0)
	{
	  printf ("round %d: rwlockattr_setkind failed\n", cnt);
	  exit (1);
	}

      if (pthread_rwlock_init (&r, &a) != 0)
	{
	  printf ("round %d: rwlock_init failed\n", cnt);
	  exit (1);
	}

      if (pthread_rwlockattr_destroy (&a) != 0)
	{
	  printf ("round %d: rwlockattr_destroy failed\n", cnt);
	  exit (1);
	}

      struct timeval tv;
      (void) gettimeofday (&tv, NULL);

      struct timespec ts;
      TIMEVAL_TO_TIMESPEC (&tv, &ts);

      ++ts.tv_sec;

      /* Get a write lock.  */
      if (pthread_rwlock_timedwrlock (&r, &ts) != 0)
	{
	  printf ("round %d: rwlock_wrlock failed\n", cnt);
	  exit (1);
	}

      pthread_t th;
      if (pthread_create (&th, NULL, tf, &r) != 0)
	{
	  printf ("round %d: create failed\n", cnt);
	  exit (1);
	}

      void *status;
      if (pthread_join (th, &status) != 0)
	{
	  printf ("round %d: join failed\n", cnt);
	  exit (1);
	}
      if (status != NULL)
	{
	  printf ("failure in round %d\n", cnt);
	  exit (1);
	}

      if (pthread_rwlock_destroy (&r) != 0)
	{
	  printf ("round %d: rwlock_destroy failed\n", cnt);
	  exit (1);
	}
    }

  return 0;
}

#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"
