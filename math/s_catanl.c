/* Return arc tangent of complex long double value.
   Copyright (C) 1997-2016 Free Software Foundation, Inc.
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

/* To avoid spurious overflows, use this definition to treat IBM long
   double as approximating an IEEE-style format.  */
#if LDBL_MANT_DIG == 106
# undef LDBL_EPSILON
# define LDBL_EPSILON 0x1p-106L
#endif

__complex__ long double
__catanl (__complex__ long double x)
{
  __complex__ long double res;
  int rcls = fpclassify (__real__ x);
  int icls = fpclassify (__imag__ x);

  if (__glibc_unlikely (rcls <= FP_INFINITE || icls <= FP_INFINITE))
    {
      if (rcls == FP_INFINITE)
	{
	  __real__ res = __copysignl (M_PI_2l, __real__ x);
	  __imag__ res = __copysignl (0.0, __imag__ x);
	}
      else if (icls == FP_INFINITE)
	{
	  if (rcls >= FP_ZERO)
	    __real__ res = __copysignl (M_PI_2l, __real__ x);
	  else
	    __real__ res = __nanl ("");
	  __imag__ res = __copysignl (0.0, __imag__ x);
	}
      else if (icls == FP_ZERO || icls == FP_INFINITE)
	{
	  __real__ res = __nanl ("");
	  __imag__ res = __copysignl (0.0, __imag__ x);
	}
      else
	{
	  __real__ res = __nanl ("");
	  __imag__ res = __nanl ("");
	}
    }
  else if (__glibc_unlikely (rcls == FP_ZERO && icls == FP_ZERO))
    {
      res = x;
    }
  else
    {
      if (fabsl (__real__ x) >= 16.0L / LDBL_EPSILON
	  || fabsl (__imag__ x) >= 16.0L / LDBL_EPSILON)
	{
	  __real__ res = __copysignl (M_PI_2l, __real__ x);
	  if (fabsl (__real__ x) <= 1.0L)
	    __imag__ res = 1.0L / __imag__ x;
	  else if (fabsl (__imag__ x) <= 1.0L)
	    __imag__ res = __imag__ x / __real__ x / __real__ x;
	  else
	    {
	      long double h = __ieee754_hypotl (__real__ x / 2.0L,
						__imag__ x / 2.0L);
	      __imag__ res = __imag__ x / h / h / 4.0L;
	    }
	}
      else
	{
	  long double den, absx, absy;

	  absx = fabsl (__real__ x);
	  absy = fabsl (__imag__ x);
	  if (absx < absy)
	    {
	      long double t = absx;
	      absx = absy;
	      absy = t;
	    }

	  if (absy < LDBL_EPSILON / 2.0L)
	    {
	      den = (1.0L - absx) * (1.0L + absx);
	      if (den == -0.0L)
		den = 0.0L;
	    }
	  else if (absx >= 1.0L)
	    den = (1.0L - absx) * (1.0L + absx) - absy * absy;
	  else if (absx >= 0.75L || absy >= 0.5L)
	    den = -__x2y2m1l (absx, absy);
	  else
	    den = (1.0L - absx) * (1.0L + absx) - absy * absy;

	  __real__ res = 0.5L * __ieee754_atan2l (2.0L * __real__ x, den);

	  if (fabsl (__imag__ x) == 1.0L
	      && fabsl (__real__ x) < LDBL_EPSILON * LDBL_EPSILON)
	    __imag__ res = (__copysignl (0.5L, __imag__ x)
			    * (M_LN2l - __ieee754_logl (fabsl (__real__ x))));
	  else
	    {
	      long double r2 = 0.0L, num, f;

	      if (fabsl (__real__ x) >= LDBL_EPSILON * LDBL_EPSILON)
		r2 = __real__ x * __real__ x;

	      num = __imag__ x + 1.0L;
	      num = r2 + num * num;

	      den = __imag__ x - 1.0L;
	      den = r2 + den * den;

	      f = num / den;
	      if (f < 0.5L)
		__imag__ res = 0.25L * __ieee754_logl (f);
	      else
		{
		  num = 4.0L * __imag__ x;
		  __imag__ res = 0.25L * __log1pl (num / den);
		}
	    }
	}

      math_check_force_underflow_complex (res);
    }

  return res;
}
weak_alias (__catanl, catanl)
