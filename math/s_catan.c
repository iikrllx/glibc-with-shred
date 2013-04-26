/* Return arc tangent of complex double value.
   Copyright (C) 1997-2013 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <complex.h>
#include <math.h>
#include <math_private.h>
#include <float.h>

__complex__ double
__catan (__complex__ double x)
{
  __complex__ double res;
  int rcls = fpclassify (__real__ x);
  int icls = fpclassify (__imag__ x);

  if (__builtin_expect (rcls <= FP_INFINITE || icls <= FP_INFINITE, 0))
    {
      if (rcls == FP_INFINITE)
	{
	  __real__ res = __copysign (M_PI_2, __real__ x);
	  __imag__ res = __copysign (0.0, __imag__ x);
	}
      else if (icls == FP_INFINITE)
	{
	  if (rcls >= FP_ZERO)
	    __real__ res = __copysign (M_PI_2, __real__ x);
	  else
	    __real__ res = __nan ("");
	  __imag__ res = __copysign (0.0, __imag__ x);
	}
      else if (icls == FP_ZERO || icls == FP_INFINITE)
	{
	  __real__ res = __nan ("");
	  __imag__ res = __copysign (0.0, __imag__ x);
	}
      else
	{
	  __real__ res = __nan ("");
	  __imag__ res = __nan ("");
	}
    }
  else if (__builtin_expect (rcls == FP_ZERO && icls == FP_ZERO, 0))
    {
      res = x;
    }
  else
    {
      double r2, num, den, f;

      r2 = __real__ x * __real__ x;

      den = 1 - r2 - __imag__ x * __imag__ x;

      __real__ res = 0.5 * __ieee754_atan2 (2.0 * __real__ x, den);

      num = __imag__ x + 1.0;
      num = r2 + num * num;

      den = __imag__ x - 1.0;
      den = r2 + den * den;

      f = num / den;
      if (f < 0.5)
	__imag__ res = 0.25 * __ieee754_log (f);
      else
	{
	  num = 4.0 * __imag__ x;
	  __imag__ res = 0.25 * __log1p (num / den);
	}

      if (fabs (__real__ res) < DBL_MIN)
	{
	  volatile double force_underflow = __real__ res * __real__ res;
	  (void) force_underflow;
	}
      if (fabs (__imag__ res) < DBL_MIN)
	{
	  volatile double force_underflow = __imag__ res * __imag__ res;
	  (void) force_underflow;
	}
    }

  return res;
}
weak_alias (__catan, catan)
#ifdef NO_LONG_DOUBLE
strong_alias (__catan, __catanl)
weak_alias (__catan, catanl)
#endif
