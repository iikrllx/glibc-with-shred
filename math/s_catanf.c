/* Return arc tangent of complex float value.
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

__complex__ float
__catanf (__complex__ float x)
{
  __complex__ float res;
  int rcls = fpclassify (__real__ x);
  int icls = fpclassify (__imag__ x);

  if (__builtin_expect (rcls <= FP_INFINITE || icls <= FP_INFINITE, 0))
    {
      if (rcls == FP_INFINITE)
	{
	  __real__ res = __copysignf (M_PI_2, __real__ x);
	  __imag__ res = __copysignf (0.0, __imag__ x);
	}
      else if (icls == FP_INFINITE)
	{
	  if (rcls >= FP_ZERO)
	    __real__ res = __copysignf (M_PI_2, __real__ x);
	  else
	    __real__ res = __nanf ("");
	  __imag__ res = __copysignf (0.0, __imag__ x);
	}
      else if (icls == FP_ZERO || icls == FP_INFINITE)
	{
	  __real__ res = __nanf ("");
	  __imag__ res = __copysignf (0.0, __imag__ x);
	}
      else
	{
	  __real__ res = __nanf ("");
	  __imag__ res = __nanf ("");
	}
    }
  else if (__builtin_expect (rcls == FP_ZERO && icls == FP_ZERO, 0))
    {
      res = x;
    }
  else
    {
      float r2, num, den, f;

      r2 = __real__ x * __real__ x;

      den = 1 - r2 - __imag__ x * __imag__ x;

      __real__ res = 0.5f * __ieee754_atan2f (2.0f * __real__ x, den);

      num = __imag__ x + 1.0f;
      num = r2 + num * num;

      den = __imag__ x - 1.0f;
      den = r2 + den * den;

      f = num / den;
      if (f < 0.5f)
	__imag__ res = 0.25f * __ieee754_logf (f);
      else
	{
	  num = 4.0f * __imag__ x;
	  __imag__ res = 0.25f * __log1pf (num / den);
	}

      if (fabsf (__real__ res) < FLT_MIN)
	{
	  volatile float force_underflow = __real__ res * __real__ res;
	  (void) force_underflow;
	}
      if (fabsf (__imag__ res) < FLT_MIN)
	{
	  volatile float force_underflow = __imag__ res * __imag__ res;
	  (void) force_underflow;
	}
    }

  return res;
}
#ifndef __catanf
weak_alias (__catanf, catanf)
#endif
