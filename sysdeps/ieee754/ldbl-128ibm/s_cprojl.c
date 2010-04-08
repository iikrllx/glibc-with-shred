/* Compute projection of complex long double value to Riemann sphere.
   Copyright (C) 1997,1999,2006,2010 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <complex.h>
#include <math.h>
#include <math_ldbl_opt.h>

__complex__ long double
__cprojl (__complex__ long double x)
{
  if (isnan (__real__ x) && isnan (__imag__ x))
    return x;
  else if (!isfinite (__real__ x) || !isfinite (__imag__ x))
    {
      __complex__ long double res;

      __real__ res = INFINITY;
      __imag__ res = __copysignl (0.0, __imag__ x);

      return res;
    }

  return x;
}
long_double_symbol (libm, __cprojl, cprojl);
