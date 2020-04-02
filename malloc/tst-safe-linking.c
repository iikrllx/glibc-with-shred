/* Test reporting of Safe-Linking caught errors.
   Copyright (C) 2020 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <support/capture_subprocess.h>
#include <support/check.h>

/* Run CALLBACK and check that the data on standard error equals
   EXPECTED.  */
static void
check (const char *test, void (*callback) (void *),
       const char *expected)
{
  int i, rand_mask;
  bool success = false;
  /* There is a chance of 1/16 that a corrupted pointer will be aligned.
     Try multiple times so that statistical failure will be improbable.  */
  for (i = 0; i < 10 && !success; ++i)
    {
      rand_mask = rand () & 0xFF;
      struct support_capture_subprocess result
	= support_capture_subprocess (callback, &rand_mask);
      /* Did not crash, could happen.  Try again.  */
      if (strlen (result.err.buffer) == 0)
	continue;
      /* Crashed, must be the expected result.  */
      if (strcmp (result.err.buffer, expected) != 0)
	{
	  support_record_failure ();
	  printf ("error: test %s unexpected standard error data\n"
	          "  expected: %s\n"
	          "  actual:   %s\n",
	          test, expected, result.err.buffer);
	}
      TEST_VERIFY (WIFSIGNALED (result.status));
      if (WIFSIGNALED (result.status))
	TEST_VERIFY (WTERMSIG (result.status) == SIGABRT);
      support_capture_subprocess_free (&result);
      success = true;
    }
  TEST_VERIFY (success);
}

/* Implementation details must be kept in sync with malloc.  */
#define TCACHE_FILL_COUNT               7
#define TCACHE_ALLOC_SIZE               0x20
#define MALLOC_CONSOLIDATE_SIZE         256*1024

/* Try corrupting the tcache list.  */
static void
test_tcache (void *closure)
{
  int mask = ((int *)closure)[0];
  size_t size = TCACHE_ALLOC_SIZE;

  /* Populate the tcache list.  */
  void * volatile a = malloc (size);
  void * volatile b = malloc (size);
  void * volatile c = malloc (size);
  free (a);
  free (b);
  free (c);

  /* Corrupt the pointer with a random value, and avoid optimizations.  */
  printf ("Before: c=%p, c[0]=%p\n", c, ((void **)c)[0]);
  memset (c, mask & 0xFF, size);
  printf ("After: c=%p, c[0]=%p\n", c, ((void **)c)[0]);

  c = malloc (size);
  /* This line will trigger the Safe-Linking check.  */
  b = malloc (size);
  printf ("b=%p\n", b);
}

/* Try corrupting the fastbin list.  */
static void
test_fastbin (void *closure)
{
  int i;
  int mask = ((int *)closure)[0];
  size_t size = TCACHE_ALLOC_SIZE;

  /* Take the tcache out of the game.  */
  for (i = 0; i < TCACHE_FILL_COUNT; ++i)
    {
      void * volatile p = calloc (1, size);
      free (p);
    }

  /* Populate the fastbin list.  */
  void * volatile a = calloc (1, size);
  void * volatile b = calloc (1, size);
  void * volatile c = calloc (1, size);
  free (a);
  free (b);
  free (c);

  /* Corrupt the pointer with a random value, and avoid optimizations.  */
  printf ("Before: c=%p, c[0]=%p\n", c, ((void **)c)[0]);
  memset (c, mask & 0xFF, size);
  printf ("After: c=%p, c[0]=%p\n", c, ((void **)c)[0]);

  c = calloc (1, size);
  /* This line will trigger the Safe-Linking check.  */
  b = calloc (1, size);
  printf ("b=%p\n", b);
}

/* Try corrupting the fastbin list and trigger a consolidate.  */
static void
test_fastbin_consolidate (void *closure)
{
  int i;
  int mask = ((int*)closure)[0];
  size_t size = TCACHE_ALLOC_SIZE;

  /* Take the tcache out of the game.  */
  for (i = 0; i < TCACHE_FILL_COUNT; ++i)
    {
      void * volatile p = calloc (1, size);
      free (p);
    }

  /* Populate the fastbin list.  */
  void * volatile a = calloc (1, size);
  void * volatile b = calloc (1, size);
  void * volatile c = calloc (1, size);
  free (a);
  free (b);
  free (c);

  /* Corrupt the pointer with a random value, and avoid optimizations.  */
  printf ("Before: c=%p, c[0]=%p\n", c, ((void **)c)[0]);
  memset (c, mask & 0xFF, size);
  printf ("After: c=%p, c[0]=%p\n", c, ((void **)c)[0]);

  /* This line will trigger the Safe-Linking check.  */
  b = malloc (MALLOC_CONSOLIDATE_SIZE);
  printf ("b=%p\n", b);
}

static int
do_test (void)
{
  /* Seed the random for the test.  */
  srand (time (NULL));

  check ("test_tcache", test_tcache,
         "malloc(): unaligned tcache chunk detected\n");
  check ("test_fastbin", test_fastbin,
         "malloc(): unaligned fastbin chunk detected 2\n");
  check ("test_fastbin_consolidate", test_fastbin_consolidate,
         "malloc_consolidate(): unaligned fastbin chunk detected\n");

  return 0;
}

#include <support/test-driver.c>
