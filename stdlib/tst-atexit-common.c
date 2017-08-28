/* Helper file for tst-{atexit,at_quick_exit,cxa_atexit,on_exit}.
   Copyright (C) 2017 Free Software Foundation, Inc.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ATEXIT 20  /* Large enough for current set of invocations.  */
static char crumbs[MAX_ATEXIT];
static int next_slot = 0;

static void
fn0 (void)
{
  crumbs[next_slot++] = '0';
}

static void
fn1 (void)
{
  crumbs[next_slot++] = '1';
}

static void
fn2 (void)
{
  crumbs[next_slot++] = '2';
  ATEXIT (fn1);
}

static void
fn3 (void)
{
  crumbs[next_slot++] = '3';
  ATEXIT (fn2);
  ATEXIT (fn0);
}

static void
fn_final (void)
{
  /* Arbitrary sequence matching current registrations.  */
  const char expected[] = "3021121130211";

  if (strcmp (crumbs, expected) == 0)
    _exit (0);

  printf ("crumbs:   %s\n", crumbs);
  printf ("expected: %s\n", expected);
  _exit (1);
}

/* This is currently just a basic test to verify that exit handlers execute
   in LIFO order, even when the handlers register additional new handlers.

   TODO: Additional tests that we should do:
   1. POSIX says we need to support at least ATEXIT_MAX
   2. Verify that fork'd child inherit the registrations of the parent.
   3. ...  */

static int
do_test (void)
{
  /* Register this first so it can verify expected order of the rest.  */
  ATEXIT (fn_final);

  ATEXIT (fn1);
  ATEXIT (fn3);
  ATEXIT (fn1);
  ATEXIT (fn2);
  ATEXIT (fn1);
  ATEXIT (fn3);

  EXIT (2);  /* If we see this exit code, fn_final must have not worked.  */
}

#define TEST_FUNCTION do_test
#include <support/test-driver.c>
