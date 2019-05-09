/* Copyright (C) 2002-2019 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <support/check.h>
#include <support/timespec.h>
#include <support/xthread.h>
#include <support/xtime.h>


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
  struct timespec ts_start;
  xclock_gettime (CLOCK_REALTIME, &ts_start);
  const struct timespec ts_timeout = timespec_add (ts_start,
                                                   make_timespec (0, 300000000));

  TEST_COMPARE (pthread_rwlock_timedwrlock (r, &ts_timeout), ETIMEDOUT);
  puts ("child: timedwrlock failed with ETIMEDOUT");

  TEST_TIMESPEC_NOW_OR_AFTER (CLOCK_REALTIME, ts_timeout);

  struct timespec ts_invalid;
  xclock_gettime (CLOCK_REALTIME, &ts_invalid);
  ts_invalid.tv_sec += 10;
  /* Note that the following operation makes ts invalid.  */
  ts_invalid.tv_nsec += 1000000000;

  TEST_COMPARE (pthread_rwlock_timedwrlock (r, &ts_invalid), EINVAL);

  puts ("child: timedwrlock failed with EINVAL");

  return NULL;
}


static int
do_test (void)
{
  size_t cnt;
  for (cnt = 0; cnt < sizeof (kind) / sizeof (kind[0]); ++cnt)
    {
      pthread_rwlock_t r;
      pthread_rwlockattr_t a;

      if (pthread_rwlockattr_init (&a) != 0)
        FAIL_EXIT1 ("round %Zu: rwlockattr_t failed\n", cnt);

      if (pthread_rwlockattr_setkind_np (&a, kind[cnt]) != 0)
        FAIL_EXIT1 ("round %Zu: rwlockattr_setkind failed\n", cnt);

      if (pthread_rwlock_init (&r, &a) != 0)
        FAIL_EXIT1 ("round %Zu: rwlock_init failed\n", cnt);

      if (pthread_rwlockattr_destroy (&a) != 0)
        FAIL_EXIT1 ("round %Zu: rwlockattr_destroy failed\n", cnt);

      struct timespec ts;
      xclock_gettime (CLOCK_REALTIME, &ts);

      ++ts.tv_sec;

      /* Get a read lock.  */
      if (pthread_rwlock_timedrdlock (&r, &ts) != 0)
        FAIL_EXIT1 ("round %Zu: rwlock_timedrdlock failed\n", cnt);

      printf ("%zu: got timedrdlock\n", cnt);

      pthread_t th;
      if (pthread_create (&th, NULL, tf, &r) != 0)
        FAIL_EXIT1 ("round %Zu: create failed\n", cnt);

      void *status;
      if (pthread_join (th, &status) != 0)
        FAIL_EXIT1 ("round %Zu: join failed\n", cnt);
      if (status != NULL)
        FAIL_EXIT1 ("failure in round %Zu\n", cnt);

      if (pthread_rwlock_destroy (&r) != 0)
        FAIL_EXIT1 ("round %Zu: rwlock_destroy failed\n", cnt);
    }

  return 0;
}

#include <support/test-driver.c>
