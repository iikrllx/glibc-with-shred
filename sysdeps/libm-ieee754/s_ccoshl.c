/* Complex cosine hyperbole function for long double.
   Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <complex.h>
#include <fenv.h>
#include <math.h>

#include "math_private.h"


__complex__ long double
__ccoshl (__complex__ long double x)
{
  __complex__ long double retval;
  int rcls = fpclassify (__real__ x);
  int icls = fpclassify (__imag__ x);

  if (rcls >= FP_ZERO)
    {
      /* Real part is finite.  */
      if (icls >= FP_ZERO)
	{
	  /* Imaginary part is finite.  */
	  long double sinh_val = __ieee754_sinhl (__real__ x);
	  long double cosh_val = __ieee754_coshl (__real__ x);
	  long double sinix, cosix;

	  __sincosl (__imag__ x, &sinix, &cosix);

	  __real__ retval = cosh_val * cosix;
	  __imag__ retval = sinh_val * sinix;
	}
      else
	{
	  __imag__ retval = __real__ x == 0.0 ? 0.0 : __nanl ("");
	  __real__ retval = __nanl ("") + __nanl ("");

#ifdef FE_INVALID
	  if (icls == FP_INFINITE)
	    feraiseexcept (FE_INVALID);
#endif
	}
    }
  else if (rcls == FP_INFINITE)
    {
      /* Real part is infinite.  */
      if (icls == FP_ZERO)
	{
	  /* Imaginary part is 0.0.  */
	  __real__ retval = HUGE_VALL;
	  __imag__ retval = __imag__ x * __copysignl (1.0, __real__ x);
	}
      else if (icls > FP_ZERO)
	{
	  /* Imaginary part is finite.  */
	  long double sinix, cosix;

	  __sincosl (__imag__ x, &sinix, &cosix);

	  __real__ retval = __copysignl (HUGE_VALL, cosix);
	  __imag__ retval = (__copysignl (HUGE_VALL, sinix)
			     * __copysignl (1.0, __real__ x));
	}
      else
	{
	  /* The addition raises the invalid exception.  */
	  __real__ retval = HUGE_VALL;
	  __imag__ retval = __nanl ("") + __nanl ("");

#ifdef FE_INVALID
	  if (icls == FP_INFINITE)
	    feraiseexcept (FE_INVALID);
#endif
	}
    }
  else
    {
      __real__ retval = __nanl ("");
      __imag__ retval = __imag__ x == 0.0 ? __imag__ x : __nanl ("");
    }

  return retval;
}
weak_alias (__ccoshl, ccoshl)
