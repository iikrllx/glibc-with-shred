/* Multiply long double (ldbl-128) values, narrowing the result to double.
   Copyright (C) 2018-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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
   <https://www.gnu.org/licenses/>.  */

#define f32xmulf64x __hide_f32xmulf64x
#define f32xmulf128 __hide_f32xmulf128
#define f64mulf64x __hide_f64mulf64x
#define f64mulf128 __hide_f64mulf128
#include <math.h>
#undef f32xmulf64x
#undef f32xmulf128
#undef f64mulf64x
#undef f64mulf128

#include <math-narrow.h>

double
__dmull (_Float128 x, _Float128 y)
{
  NARROW_MUL_ROUND_TO_ODD (x, y, double, union ieee854_long_double, l,
			   mantissa3, false);
}
libm_alias_double_ldouble (mul)
