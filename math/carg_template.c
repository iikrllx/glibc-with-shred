/* Compute argument of complex float type.
   Copyright (C) 1997-2017 Free Software Foundation, Inc.
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

FLOAT
M_DECL_FUNC (__carg) (CFLOAT x)
{
  return M_SUF (__atan2) (__imag__ x, __real__ x);
}

declare_mgen_alias (__carg, carg)

#if M_LIBM_NEED_COMPAT (carg)
declare_mgen_libm_compat (__carg, carg)
#endif
