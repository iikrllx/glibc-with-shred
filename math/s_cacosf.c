/* Return cosine of complex float value.
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

__complex__ float
__cacosf (__complex__ float x)
{
  __complex__ float y;
  __complex__ float res;

  y = __casinf (x);

  __real__ res = (float) M_PI_2 - __real__ y;
  __imag__ res = -__imag__ y;

  return res;
}
#ifndef __cacosf
weak_alias (__cacosf, cacosf)
#endif
