/* Test for ldbl-128ibm fmodl handling of equal values (bug 19602).
   Copyright (C) 2016 Free Software Foundation, Inc.
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

#include <float.h>
#include <math.h>
#include <stdio.h>

union u
{
  long double ld;
  double d[2];
};

volatile union u p1 = { .d = { DBL_MIN, 0.0 } };
volatile union u p2 = { .d = { DBL_MIN, -0.0 } };
volatile union u m1 = { .d = { -DBL_MIN, 0.0 } };
volatile union u m2 = { .d = { -DBL_MIN, -0.0 } };

static int
test_fmodl (const char *s, long double x, long double y, long double expected)
{
  volatile long double r;
  r = fmodl (x, y);
  if (r != expected || copysignl (1.0, r) != copysignl (1.0, expected))
    {
      printf ("FAIL: fmodl (%s)\n", s);
      return 1;
    }
  else
    {
      printf ("PASS: fmodl (%s)\n", s);
      return 0;
    }
}

#define TEST_FMODL(a, b, e) test_fmodl (#a ", " #b, a, b, e)

static int
do_test (void)
{
  int result = 0;
  result |= TEST_FMODL (p1.ld, p1.ld, 0.0L);
  result |= TEST_FMODL (p1.ld, p2.ld, 0.0L);
  result |= TEST_FMODL (p1.ld, m1.ld, 0.0L);
  result |= TEST_FMODL (p1.ld, m2.ld, 0.0L);
  result |= TEST_FMODL (p2.ld, p1.ld, 0.0L);
  result |= TEST_FMODL (p2.ld, p2.ld, 0.0L);
  result |= TEST_FMODL (p2.ld, m1.ld, 0.0L);
  result |= TEST_FMODL (p2.ld, m2.ld, 0.0L);
  result |= TEST_FMODL (m1.ld, p1.ld, -0.0L);
  result |= TEST_FMODL (m1.ld, p2.ld, -0.0L);
  result |= TEST_FMODL (m1.ld, m1.ld, -0.0L);
  result |= TEST_FMODL (m1.ld, m2.ld, -0.0L);
  result |= TEST_FMODL (m2.ld, p1.ld, -0.0L);
  result |= TEST_FMODL (m2.ld, p2.ld, -0.0L);
  result |= TEST_FMODL (m2.ld, m1.ld, -0.0L);
  result |= TEST_FMODL (m2.ld, m2.ld, -0.0L);
  return result;
}

#define TEST_FUNCTION do_test ()
#include "../../../test-skeleton.c"
