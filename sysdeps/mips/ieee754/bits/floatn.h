/* Macros to control TS 18661-3 glibc features on MIPS platforms.
   Copyright (C) 2017 Free Software Foundation, Inc.
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

#ifndef _BITS_FLOATN_H
#define _BITS_FLOATN_H

#include <features.h>
#include <bits/long-double.h>

/* Defined to 1 if the current compiler invocation provides a
   floating-point type with the IEEE 754 binary128 format, and this
   glibc includes corresponding *f128 interfaces for it.  */
#ifndef __NO_LONG_DOUBLE_MATH
# define __HAVE_FLOAT128 1
#else
/* glibc does not support _Float128 for platforms where long double is
   normally binary128 when building with long double as binary64.
   GCC's default for supported scalar modes does not support it either
   in that case.  */
# define __HAVE_FLOAT128 0
#endif

/* Defined to 1 if __HAVE_FLOAT128 is 1 and the type is ABI-distinct
   from the default float, double and long double types in this glibc.  */
#define __HAVE_DISTINCT_FLOAT128 0

/* Defined to concatenate the literal suffix to be used with _Float128
   types, if __HAVE_FLOAT128 is 1. */
#if __HAVE_FLOAT128
# if !__GNUC_PREREQ (7, 0) || defined __cplusplus
/* The literal suffix f128 exists only since GCC 7.0.  */
#  define __f128(x) x##l
# else
#  define __f128(x) x##f128
# endif
#endif

/* Defined to a complex binary128 type if __HAVE_FLOAT128 is 1.  */
#if __HAVE_FLOAT128
# if !__GNUC_PREREQ (7, 0) || defined __cplusplus
#  define __CFLOAT128 _Complex long double
# else
#  define __CFLOAT128 _Complex _Float128
# endif
#endif

/* The remaining of this file provides support for older compilers.  */
#if __HAVE_FLOAT128

/* The type _Float128 exists only since GCC 7.0.  */
# if !__GNUC_PREREQ (7, 0) || defined __cplusplus
typedef long double _Float128;
# endif

/* Various built-in functions do not exist before GCC 7.0.  */
# if !__GNUC_PREREQ (7, 0)
#  define __builtin_huge_valf128() (__builtin_huge_vall ())
#  define __builtin_inff128() (__builtin_infl ())
#  define __builtin_nanf128(x) (__builtin_nanl (x))
#  define __builtin_nansf128(x) (__builtin_nansl (x))
# endif

#endif

#include <bits/floatn-common.h>

#endif /* _BITS_FLOATN_H */
