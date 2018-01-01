/* Long double square root, sparc64 version.
   Copyright (C) 2000-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jakub Jelinek <jakub@redhat.com>, 2000.

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

#include <math.h>

extern void _Qp_sqrt(long double *, const long double *);

long double
__ieee754_sqrtl (long double x)
{
  long double ret;
  _Qp_sqrt (&ret, &x);
  return ret;
}
strong_alias (__ieee754_sqrtl, __sqrtl_finite)
