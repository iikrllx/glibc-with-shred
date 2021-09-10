/* Square root of double value, narrowing the result to float, using soft-fp.
   Copyright (C) 2021 Free Software Foundation, Inc.
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

#define f32sqrtf64 __hide_f32sqrtf64
#define f32sqrtf32x __hide_f32sqrtf32x
#define fsqrtl __hide_fsqrtl
#include <math.h>
#undef f32sqrtf64
#undef f32sqrtf32x
#undef fsqrtl

#include <math-narrow.h>
#include <soft-fp.h>
#include <single.h>
#include <double.h>

float
__fsqrt (double x)
{
  FP_DECL_EX;
  FP_DECL_D (X);
  FP_DECL_D (R);
  FP_DECL_S (RN);
  float ret;

  FP_INIT_ROUNDMODE;
  FP_UNPACK_D (X, x);
  FP_SQRT_D (R, X);
#if _FP_W_TYPE_SIZE < _FP_FRACBITS_D
  FP_TRUNC_COOKED (S, D, 1, 2, RN, R);
#else
  FP_TRUNC_COOKED (S, D, 1, 1, RN, R);
#endif
  FP_PACK_S (ret, RN);
  FP_HANDLE_EXCEPTIONS;
  CHECK_NARROW_SQRT (ret, x);
  return ret;
}
libm_alias_float_double (sqrt)
