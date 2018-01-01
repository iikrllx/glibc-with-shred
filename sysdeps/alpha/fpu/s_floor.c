/* Copyright (C) 1998-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Richard Henderson.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

#include <math.h>
#include <math_ldbl_opt.h>
#include <libm-alias-double.h>


/* Use the -inf rounding mode conversion instructions to implement
   floor.  We note when the exponent is large enough that the value
   must be integral, as this avoids unpleasant integer overflows.  */

double
__floor (double x)
{
  if (isnan (x))
    return x + x;

  if (isless (fabs (x), 9007199254740992.0))	/* 1 << DBL_MANT_DIG */
    {
      double tmp1, new_x;

      __asm (
	     "cvttq/svm %2,%1\n\t"
	     "cvtqt/m %1,%0\n\t"
	     : "=f"(new_x), "=&f"(tmp1)
	     : "f"(x));

      /* floor(-0) == -0, and in general we'll always have the same
	 sign as our input.  */
      x = copysign(new_x, x);
    }
  return x;
}

libm_alias_double (__floor, floor)
