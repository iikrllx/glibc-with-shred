/* Compute complex natural logarithm.
   Copyright (C) 1997-2012 Free Software Foundation, Inc.
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
__clogf (__complex__ float x)
{
  __complex__ float result;
  int rcls = fpclassify (__real__ x);
  int icls = fpclassify (__imag__ x);

  if (__builtin_expect (rcls == FP_ZERO && icls == FP_ZERO, 0))
    {
      /* Real and imaginary part are 0.0.  */
      __imag__ result = signbit (__real__ x) ? M_PI : 0.0;
      __imag__ result = __copysignf (__imag__ result, __imag__ x);
      /* Yes, the following line raises an exception.  */
      __real__ result = -1.0 / fabsf (__real__ x);
    }
  else if (__builtin_expect (rcls != FP_NAN && icls != FP_NAN, 1))
    {
      /* Neither real nor imaginary part is NaN.  */
      float d;
      int scale = 0;

      if (fabsf (__real__ x) > FLT_MAX / 2.0f
	  || fabsf (__imag__ x) > FLT_MAX / 2.0f)
	{
	  scale = -1;
	  __real__ x = __scalbnf (__real__ x, scale);
	  __imag__ x = __scalbnf (__imag__ x, scale);
	}
      else if (fabsf (__real__ x) < FLT_MIN
	       && fabsf (__imag__ x) < FLT_MIN)
	{
	  scale = FLT_MANT_DIG;
	  __real__ x = __scalbnf (__real__ x, scale);
	  __imag__ x = __scalbnf (__imag__ x, scale);
	}

      d = __ieee754_hypotf (__real__ x, __imag__ x);

      __real__ result = __ieee754_logf (d) - scale * (float) M_LN2;
      __imag__ result = __ieee754_atan2f (__imag__ x, __real__ x);
    }
  else
    {
      __imag__ result = __nanf ("");
      if (rcls == FP_INFINITE || icls == FP_INFINITE)
	/* Real or imaginary part is infinite.  */
	__real__ result = HUGE_VALF;
      else
	__real__ result = __nanf ("");
    }

  return result;
}
#ifndef __clogf
weak_alias (__clogf, clogf)
#endif
