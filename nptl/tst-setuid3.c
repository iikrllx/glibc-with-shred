/* Copyright (C) 2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

/* The test must run under a non-privileged user ID.  */
static const uid_t test_uid = 1;

static pthread_barrier_t barrier1;
static pthread_barrier_t barrier2;

static void *
thread_func (void *ctx __attribute__ ((unused)))
{
  int ret = pthread_barrier_wait (&barrier1);
  if (ret != PTHREAD_BARRIER_SERIAL_THREAD && ret != 0)
    errx (1, "pthread_barrier_wait (barrier1) (on thread): %d", ret);
  ret = pthread_barrier_wait (&barrier2);
  if (ret != PTHREAD_BARRIER_SERIAL_THREAD && ret != 0)
    errx (1, "pthread_barrier_wait (barrier2) (on thread): %d", ret);
  return NULL;
}

static void
setuid_failure (int phase)
{
  int ret = setuid (0);
  switch (ret)
    {
    case 0:
      errx (1, "setuid succeeded unexpectedly in phase %d", phase);
    case -1:
      if (errno != EPERM)
	err (1, "setuid phase %d", phase);
      break;
    default:
      errx (1, "invalid setuid return value in phase %d: %d", phase, ret);
    }
}

static int
do_test (void)
{
  if (getuid () == 0)
    if (setuid (test_uid) != 0)
      err (1, "setuid (%u)", (unsigned) test_uid);
  if (setuid (getuid ()))
    err (1, "setuid (getuid ())");
  setuid_failure (1);

  int ret = pthread_barrier_init (&barrier1, NULL, 2);
  if (ret != 0)
    errx (1, "pthread_barrier_init (barrier1): %d", ret);
  ret = pthread_barrier_init (&barrier2, NULL, 2);
  if (ret != 0)
    errx (1, "pthread_barrier_init (barrier2): %d", ret);

  pthread_t thread;
  ret = pthread_create (&thread, NULL, thread_func, NULL);
  if (ret != 0)
    errx (1, "pthread_create: %d", ret);

  /* Ensure that the thread is running properly.  */
  ret = pthread_barrier_wait (&barrier1);
  if (ret != 0)
    errx (1, "pthread_barrier_wait (barrier1): %d", ret);

  setuid_failure (2);

  /* Check success case. */
  if (setuid (getuid ()) != 0)
    err (1, "setuid (getuid ())");

  /* Shutdown.  */
  ret = pthread_barrier_wait (&barrier2);
  if (ret != PTHREAD_BARRIER_SERIAL_THREAD && ret != 0)
    errx (1, "pthread_barrier_wait (barrier2): %d", ret);

  if (ret != PTHREAD_BARRIER_SERIAL_THREAD && ret != 0)
    errx (1, "pthread_join: %d", ret);

  return 0;
}

#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"
