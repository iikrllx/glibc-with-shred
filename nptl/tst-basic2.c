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

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>


#define N 20

static pthread_t th[N];
static pthread_mutex_t lock[N];


static void *tf (void *a)
{
  uintptr_t idx = (uintptr_t) a;

  pthread_mutex_lock (&lock[idx]);

  return pthread_equal (pthread_self (), th[idx]) ? NULL : (void *) 1l;
}


int
do_test (void)
{
  if (pthread_equal (pthread_self (), pthread_self ()) == 0)
    {
      puts ("pthread_equal (pthread_self (), pthread_self ()) failed");
      exit (1);
    }

  int i;
  for (i = 0; i < N; ++i)
    {
      if (pthread_mutex_init (&lock[i], NULL) != 0)
	{
	  puts ("mutex_init failed");
	  exit (1);
	}

      if (pthread_mutex_lock (&lock[i]) != 0)
	{
	  puts ("mutex_lock failed");
	  exit (1);
	}

      if (pthread_create (&th[i], NULL, tf, (void *) i) != 0)
	{
	  puts ("create failed");
	  exit (1);
	}

      if (pthread_mutex_unlock (&lock[i]) != 0)
	{
	  puts ("mutex_unlock failed");
	  exit (1);
	}

      printf ("created thread %d\n", i);
    }

  int result = 0;
  for (i = 0; i < N; ++i)
    {
      void *r;
      int e;
      if ((e = pthread_join (th[i], &r)) != 0)
	{
	  printf ("join failed: %d\n", e);
	  _exit (1);
	}
      else if (r != NULL)
	result = 1;
    }

  return 0;
}


#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"
