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
#include <math.h>


__complex__ long double
__ccoshl (__complex__ long double x)
{
  __complex__ long double retval;

  __real__ x = fabsl (__real__ x);

  if (isfinite (__real__ x))
    {
      if (isfinite (__imag__ x))
	{
	  long double exp_val = __expl (__real__ x);
	  long double rec_exp_val = 1.0 / exp_val;

	  __real__ retval = (0.5 * (exp_val + rec_exp_val)
			     * __cosl (__imag__ x));
	  __imag__ retval = (0.5 * (exp_val + rec_exp_val)
			     * __sinl (__imag__ x));
	}
      else
	{
	  if (__real__ x == 0)
	    {
	      __imag__ retval = 0.0;
	      __real__ retval = __nanl ("") + __nanl ("");
	    }
	  else
	    {
	      __real__ retval = __nanl ("");
	      __imag__ retval = __nanl ("") + __nanl ("");
	    }
	}
    }
  else if (__isinfl (__real__ x))
    {
      if (__imag__ x == 0.0)
	{
	  __real__ retval = HUGE_VALL;
	  __imag__ retval = __imag__ x;
	}
      else if (isfinite (__imag__ x))
	{
	  __real__ retval = __copysignl (HUGE_VALL, __cosl (__imag__ x));
	  __imag__ retval = __copysignl (HUGE_VALL, __sinl (__imag__ x));
	}
      else
	{
	  /* The addition raises the invalid exception.  */
	  __real__ retval = HUGE_VALL;
	  __imag__ retval = __nanl ("") + __nanl ("");
	}
    }
  else
    {
      if (__imag__ x == 0.0)
	{
	  __real__ retval = __nanl ("");
	  __imag__ retval = __imag__ x;
	}
      else
	{
	  __real__ retval = __nanl ("");
	  __imag__ retval = __nanl ("");
	}
    }

  return retval;
}
weak_alias (__ccoshl, ccoshl)
