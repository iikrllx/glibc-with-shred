/* Copyright (C) 1997-2016 Free Software Foundation, Inc.
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

#if !defined _MATH_H && !defined _COMPLEX_H
# error "Never use <bits/mathdef.h> directly; include <math.h> instead"
#endif

#if defined  __USE_ISOC99 && defined _MATH_H && !defined _MATH_H_MATHDEF
# define _MATH_H_MATHDEF	1

/* Normally, there is no long double type and the `float' and `double'
   expressions are evaluated as `double'.  */
typedef double float_t;		/* `float' expressions are evaluated as
				   `double'.  */
typedef double double_t;	/* `double' expressions are evaluated as
				   `double'.  */

/* The values returned by `ilogb' for 0 and NaN respectively.  */
# define FP_ILOGB0	(-2147483647)
# define FP_ILOGBNAN	2147483647

/* The GCC 4.6 compiler will define __FP_FAST_FMA{,F,L} if the fma{,f,l}
   builtins are supported.  */
#ifdef __FP_FAST_FMA
# define FP_FAST_FMA 1
#endif

#ifdef __FP_FAST_FMAF
# define FP_FAST_FMAF 1
#endif

#ifdef __FP_FAST_FMAL
# define FP_FAST_FMAL 1
#endif

#endif	/* ISO C99 */

#ifndef __NO_LONG_DOUBLE_MATH
/* Signal that we do not really have a `long double'.  The disables the
   declaration of all the `long double' function variants.  */
# define __NO_LONG_DOUBLE_MATH	1
#endif
