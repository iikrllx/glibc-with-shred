/* Complex sine function for long double.
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
__csinl (__complex__ long double x)
{
  __complex__ long double res;

  if (!isfinite (__real__ x) || isnan (__imag__ x))
    {
      if (__real__ x == 0.0 || __imag__ x == 0.0)
	{
	  __real__ res = __nanl ("");
	  __imag__ res = 0.0;
	}
      else if (__isinfl (__imag__ x))
	{
	  __real__ res = __nanl ("");
	  __imag__ res = __imag__ x;
	}
      else
	{
	  __real__ res = __nanl ("");
	  __imag__ res = __nanl ("");
	}
    }
  else
    {
      __complex__ long double y;

      __real__ y = -__imag__ x;
      __imag__ y = __real__ x;

      y = __csinhl (y);

      __real__ res = __imag__ y;
      __imag__ res = -__real__ y;
    }

  return res;
}
weak_alias (__csinl, csinl)
