/* Return value of complex exponential function for float complex value.
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
#include <math.h>

#include "math_private.h"


__complex__ float
__cexpf (__complex__ float x)
{
  __complex__ float retval;
  int rcls = fpclassify (__real__ x);
  int icls = fpclassify (__imag__ x);

  if (rcls >= FP_ZERO)
    {
      /* Real part is finite.  */
      if (icls >= FP_ZERO)
	{
	  /* Imaginary part is finite.  */
	  float exp_val = __ieee754_expf (__real__ x);

	  if (isfinite (exp_val))
	    {
	      __real__ retval = exp_val * __cosf (__imag__ x);
	      __imag__ retval = exp_val * __sinf (__imag__ x);
	    }
	  else
	    {
	      __real__ retval = __copysignf (exp_val, __cosf (__imag__ x));
	      __imag__ retval = __copysignf (exp_val, __sinf (__imag__ x));
	    }
	}
      else
	{
	  /* If the imaginary part is +-inf or NaN and the real part
	     is not +-inf the result is NaN + iNaN.  */
	  __real__ retval = __nanf ("");
	  __imag__ retval = __nanf ("");
	}
    }
  else if (rcls == FP_INFINITE)
    {
      /* Real part is infinite.  */
      if (icls >= FP_ZERO)
	{
	  /* Imaginary part is finite.  */
	  float value = signbit (__real__ x) ? 0.0 : HUGE_VALF;

	  if (icls == FP_ZERO)
	    {
	      /* Imaginary part is 0.0.  */
	      __real__ retval = value;
	      __imag__ retval = __imag__ x;
	    }
	  else
	    {
	      __real__ retval = __copysignf (value, __cosf (__imag__ x));
	      __imag__ retval = __copysignf (value, __sinf (__imag__ x));
	    }
	}
      else if (signbit (__real__ x) == 0)
	{
	  __real__ retval = HUGE_VALF;
	  __imag__ retval = __nanf ("");
	}
      else
	{
	  __real__ retval = 0.0;
	  __imag__ retval = __copysignf (0.0, __imag__ x);
	}
    }
  else
    {
      /* If the real part is NaN the result is NaN + iNaN.  */
      __real__ retval = __nanf ("");
      __imag__ retval = __nanf ("");
    }

  return retval;
}
weak_alias (__cexpf, cexpf)
