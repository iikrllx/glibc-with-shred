/* Common definitions for libm tests for _Float128.

   Copyright (C) 2017-2018 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.  */

#include "test-math-floatn.h"

/* Fixup builtins and constants for older compilers.  */
#include <bits/floatn.h>
#include <float.h>

#define FUNC(function) function ## f128
#define FLOAT _Float128
#define CFLOAT __CFLOAT128
#define BUILD_COMPLEX(real, imag) (CMPLXF128 ((real), (imag)))
#define PREFIX FLT128
#if FLT128_MANT_DIG == LDBL_MANT_DIG
# define TYPE_STR "ldouble"
# define ULP_IDX ULP_LDBL
# define ULP_I_IDX ULP_I_LDBL
#else
# define TYPE_STR "float128"
# define ULP_IDX ULP_FLT128
# define ULP_I_IDX ULP_I_FLT128
#endif
#define LIT(x) __f128 (x)
#define LITM(x) x ## f128
#define FTOSTR strfromf128
#define snan_value_MACRO SNANF128
#define FUNC_NARROW_PREFIX f128
