/* Copyright (C) 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

int error_count;

typedef struct
{
  double value;
  int ndigit;
  int decpt;
  char result[30];
} testcase;

typedef char * ((*efcvt_func) (double, int, int *, int *));


static testcase ecvt_tests[] =
{
  { 0.0, 0, 1, "" },
  { 10.0, 0, 2, "" },
  { 10.0, 1, 2, "1" },
  { 10.0, 5, 2, "10000" },
  { -12.0, 5, 2, "12000" },
  { 0.2, 4, 0, "2000" },
  { 0.02, 4, -1, "2000" },
  { 5.5, 1, 1, "6" },
  { 1.0, -1, 1, "" },
  { 0.01, 2, -1, "10" },
  { 100.0, -2, 3, "" },
  { 100.0, -5, 3, "" },
  { 100.0, -4, 3, "" },
  { 100.01, -4, 3, "" },
  { 123.01, -4, 3, "" },
  { 126.71, -4, 3, "" },
  { 0.0, 4, 1, "0000" },
  { 92.0, 16, 2, "920000000000000" },
  /* -1.0 is end marker.  */
  { -1.0, 0, 0, "" }
};

static testcase fcvt_tests[] =
{
  { 0.0, 0, 1, "0" },
  { 10.0, 0, 2, "10" },
  { 10.0, 1, 2, "100" },
  { 10.0, 4, 2, "100000" },
  { -12.0, 5, 2, "1200000" },
  { 0.2, 4, 0, "2000" },
  { 0.02, 4, -1, "200" },
  { 5.5, 1, 1, "55" },
  { 5.5, 0, 1, "6" },
  { 0.01, 2, -1, "1" },
  { 100.0, -2, 3, "100" },
  { 100.0, -5, 3, "100" },
  { 100.0, -4, 3, "100" },
  { 100.01, -4, 3, "100" },
  { 123.01, -4, 3, "100" },
  { 126.71, -4, 3, "100" },
  /* -1.0 is end marker.  */
  { -1.0, 0, 0, "" }
};

void
output_error (const char *name, double value, int ndigit,
	      const char *exp_p, int exp_decpt, int exp_sign,
	      char *res_p, int res_decpt, int res_sign)
{
  printf ("%s returned wrong result for value: %f, ndigits: %d\n",
	  name, value, ndigit);
  printf ("Result was p: \"%s\", decpt: %d, sign: %d\n",
	  res_p, res_decpt, res_sign);
  printf ("Should be  p: \"%s\", decpt: %d, sign: %d\n",
	  exp_p, exp_decpt, exp_sign);
  ++error_count;
}

void
test (testcase tests[], efcvt_func efcvt, const char *name)
{
  int no = 0;
  int decpt, sign;
  char *p;

  while (tests[no].value != -1.0)
    {
      p = efcvt (tests[no].value, tests[no].ndigit, &decpt, &sign);
      if (decpt != tests[no].decpt
	  || sign != (tests[no].value < 0)
	  || strcmp (p, tests[no].result) != 0)
	output_error (name, tests[no].value, tests[no].ndigit,
		      tests[no].result, tests[no].decpt,
		      (tests[no].value < 0),
		      p, decpt, sign);
      ++no;
    }
}

void
special (void)
{
  int decpt, sign;
  char *p;

  p = ecvt (NAN, 10, &decpt, &sign);
  if (sign != 0 || strcmp (p, "nan") != 0)
    output_error ("ecvt", NAN, 10, "nan", 0, 0, p, decpt, sign);

  p = ecvt (INFINITY, 10, &decpt, &sign);
  if (sign != 0 || strcmp (p, "inf") != 0)
    output_error ("ecvt", NAN, 10, "inf", 0, 0, p, decpt, sign);

  /* Simply make sure these calls with large NDIGITs don't crash.  */
  (void) ecvt (123.456, 10000, &decpt, &sign);
  (void) fcvt (123.456, 10000, &decpt, &sign);

}


int
main (void)
{
  test (ecvt_tests, ecvt, "ecvt");
  test (fcvt_tests, fcvt, "fcvt");
  special ();

  return error_count;
}
