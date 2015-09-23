/* Return arc tangent of complex float value.
   Copyright (C) 1997-2015 Free Software Foundation, Inc.
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

  if (__glibc_unlikely (rcls <= FP_INFINITE || icls <= FP_INFINITE))
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
  else if (__glibc_unlikely (rcls == FP_ZERO && icls == FP_ZERO))
    {
      res = x;
    }
  else
    {
      if (fabsf (__real__ x) >= 16.0f / FLT_EPSILON
	  || fabsf (__imag__ x) >= 16.0f / FLT_EPSILON)
	{
	  __real__ res = __copysignf ((float) M_PI_2, __real__ x);
	  if (fabsf (__real__ x) <= 1.0f)
	    __imag__ res = 1.0f / __imag__ x;
	  else if (fabsf (__imag__ x) <= 1.0f)
	    __imag__ res = __imag__ x / __real__ x / __real__ x;
	  else
	    {
	      float h = __ieee754_hypotf (__real__ x / 2.0f,
					  __imag__ x / 2.0f);
	      __imag__ res = __imag__ x / h / h / 4.0f;
	    }
	}
      else
	{
	  float den, absx, absy;

	  absx = fabsf (__real__ x);
	  absy = fabsf (__imag__ x);
	  if (absx < absy)
	    {
	      float t = absx;
	      absx = absy;
	      absy = t;
	    }

	  if (absy < FLT_EPSILON / 2.0f)
	    {
	      den = (1.0f - absx) * (1.0f + absx);
	      if (den == -0.0f)
		den = 0.0f;
	    }
	  else if (absx >= 1.0f)
	    den = (1.0f - absx) * (1.0f + absx) - absy * absy;
	  else if (absx >= 0.75f || absy >= 0.5f)
	    den = -__x2y2m1f (absx, absy);
	  else
	    den = (1.0f - absx) * (1.0f + absx) - absy * absy;

	  __real__ res = 0.5f * __ieee754_atan2f (2.0f * __real__ x, den);

	  if (fabsf (__imag__ x) == 1.0f
	      && fabsf (__real__ x) < FLT_EPSILON * FLT_EPSILON)
	    __imag__ res = (__copysignf (0.5f, __imag__ x)
			    * ((float) M_LN2
			       - __ieee754_logf (fabsf (__real__ x))));
	  else
	    {
	      float r2 = 0.0f, num, f;

	      if (fabsf (__real__ x) >= FLT_EPSILON * FLT_EPSILON)
		r2 = __real__ x * __real__ x;

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
	    }
	}

      math_check_force_underflow_complex (res);
    }

  return res;
}
#ifndef __catanf
weak_alias (__catanf, catanf)
#endif
