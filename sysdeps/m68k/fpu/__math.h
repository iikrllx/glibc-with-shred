/* Copyright (C) 1991, 1992, 1993, 1994 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifdef	__GNUC__

#include <sys/cdefs.h>
#define __need_Emath
#include <errno.h>

#ifdef	__NO_MATH_INLINES
/* This is used when defining the functions themselves.  Define them with
   __ names, and with `static inline' instead of `extern inline' so the
   bodies will always be used, never an external function call.  */
#define	__m81_u(x)	__CONCAT(__,x)
#define __m81_inline	static __inline
#else
#define	__m81_u(x)	x
#define __m81_inline	extern __inline
#define	__MATH_INLINES	1
#endif

#define	__inline_mathop2(func, op)					      \
  __m81_inline double							      \
  __m81_u(func)(double __mathop_x) __attribute__((__const__));		      \
  __m81_inline double							      \
  __m81_u(func)(double __mathop_x)					      \
  {									      \
    double __result;							      \
    __asm("f" __STRING(op) "%.x %1, %0" : "=f" (__result) : "f" (__mathop_x));\
    return __result;							      \
  }
#define	__inline_mathop(op)		__inline_mathop2(op, op)

__inline_mathop(acos)
__inline_mathop(asin)
__inline_mathop(atan)
__inline_mathop(cos)
__inline_mathop(sin)
__inline_mathop(tan)
__inline_mathop(cosh)
__inline_mathop(sinh)
__inline_mathop(tanh)
__inline_mathop2(exp, etox)
__inline_mathop2(fabs, abs)
__inline_mathop(log10)
__inline_mathop2(log, logn)
__inline_mathop(sqrt)

__inline_mathop2(__rint, int)
__inline_mathop2(__expm1, etoxm1)

#ifdef	__USE_MISC
#ifndef __NO_MATH_INLINES
__inline_mathop2(rint, int)
__inline_mathop2(expm1, etoxm1)
#endif
__inline_mathop2(log1p, lognp1)
__inline_mathop(atanh)
#endif

__m81_inline double
__m81_u(__drem)(double __x, double __y) __attribute__ ((__const__));
__m81_inline double
__m81_u(__drem)(double __x, double __y)
{
  double __result;
  __asm("frem%.x %1, %0" : "=f" (__result) : "f" (__y), "0" (__x));
  return __result;
}

__m81_inline double
__m81_u(ldexp)(double __x, int __e) __attribute__ ((__const__));
__m81_inline double
__m81_u(ldexp)(double __x, int __e)
{
  double __result;
  double __double_e = (double) __e;
  __asm("fscale%.x %1, %0" : "=f" (__result) : "f" (__double_e), "0" (__x));
  return __result;
}

__m81_inline double
__m81_u(fmod)(double __x, double __y) __attribute__ ((__const__));
__m81_inline double
__m81_u(fmod)(double __x, double __y)
{
  double __result;
  __asm("fmod%.x %1, %0" : "=f" (__result) : "f" (__y), "0" (__x));
  return __result;
}

__m81_inline double
__m81_u(frexp)(double __value, int *__expptr)
{
  double __mantissa, __exponent;
  __asm("fgetexp%.x %1, %0" : "=f" (__exponent) : "f" (__value));
  __asm("fgetman%.x %1, %0" : "=f" (__mantissa) : "f" (__value));
  *__expptr = (int) __exponent;
  return __mantissa;
}

__m81_inline double
__m81_u(floor)(double __x) __attribute__ ((__const__));
__m81_inline double
__m81_u(floor)(double __x)
{
  double __result;
  unsigned long int __ctrl_reg;
  __asm __volatile__ ("fmove%.l %!, %0" : "=dm" (__ctrl_reg));
  /* Set rounding towards negative infinity.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */ 
		      : "dmi" ((__ctrl_reg & ~0x10) | 0x20));
  /* Convert X to an integer, using -Inf rounding.  */
  __asm __volatile__ ("fint%.x %1, %0" : "=f" (__result) : "f" (__x));
  /* Restore the previous rounding mode.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg));
  return __result;
}

__m81_inline double
__m81_u(pow)(double __x, double __y) __attribute__ ((__const__));
__m81_inline double
__m81_u(pow)(double __x, double __y)
{
  double __result;
  if (__x == 0.0)
    {
      if (__y <= 0.0)
	__result = __infnan (EDOM);
      else
	__result = 0.0;
    }
  else if (__y == 0.0 || __x == 1.0)
    __result = 1.0;
  else if (__y == 1.0)
    __result = __x;
  else if (__y == 2.0)
    __result = __x * __x;
  else if (__x == 10.0)
    __asm("ftentox%.x %1, %0" : "=f" (__result) : "f" (__y));
  else if (__x == 2.0)
    __asm("ftwotox%.x %1, %0" : "=f" (__result) : "f" (__y));
  else if (__x < 0.0)
    {
      double __temp = __m81_u (__rint) (__y);
      if (__y == __temp)
	{
	  int i = (int) __y;
	  __result = __m81_u (exp) (__y * __m81_u (log) (-__x));
	  if (i & 1)
	    __result = -__result;
	}
      else
	__result = __infnan (EDOM);
    }
  else
    __result = __m81_u(exp)(__y * __m81_u(log)(__x));
  return __result;
}

__m81_inline double
__m81_u(ceil)(double __x) __attribute__ ((__const__));
__m81_inline double
__m81_u(ceil)(double __x)
{
  double __result;
  unsigned long int __ctrl_reg;
  __asm __volatile__ ("fmove%.l %!, %0" : "=dm" (__ctrl_reg));
  /* Set rounding towards positive infinity.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg | 0x30));
  /* Convert X to an integer, using +Inf rounding.  */
  __asm __volatile__ ("fint%.x %1, %0" : "=f" (__result) : "f" (__x));
  /* Restore the previous rounding mode.  */
  __asm __volatile__ ("fmove%.l %0, %!" : /* No outputs.  */
		      : "dmi" (__ctrl_reg));
  return __result;
}

__m81_inline double
__m81_u(modf)(double __value, double *__iptr)
{
  double __modf_int = __m81_u(floor)(__value);
  *__iptr = __modf_int;
  return __value - __modf_int;
}

__m81_inline int
__m81_u(__isinf)(double __value) __attribute__ ((__const__));
__m81_inline int
__m81_u(__isinf)(double __value)
{
  /* There is no branch-condition for infinity,
     so we must extract and examine the condition codes manually.  */
  unsigned long int __fpsr;
  __asm("ftst%.x %1\n"
	"fmove%.l %/fpsr, %0" : "=dm" (__fpsr) : "f" (__value));
  return (__fpsr & (2 << (3 * 8))) ? (__value < 0 ? -1 : 1) : 0;
}

__m81_inline int
__m81_u(__isnan)(double __value) __attribute__ ((__const__));
__m81_inline int
__m81_u(__isnan)(double __value)
{
  char __result;
  __asm("ftst%.x %1\n"
	"fsun %0" : "=dm" (__result) : "f" (__value));
  return __result;
}

__m81_inline int
__m81_u(__isinfl)(long double __value) __attribute__ ((__const__));
__m81_inline int
__m81_u(__isinfl)(long double __value)
{
  /* There is no branch-condition for infinity,
     so we must extract and examine the condition codes manually.  */
  unsigned long int __fpsr;
  __asm("ftst%.x %1\n"
	"fmove%.l %/fpsr, %0" : "=dm" (__fpsr) : "f" (__value));
  return (__fpsr & (2 << (3 * 8))) ? (__value < 0 ? -1 : 1) : 0;
}

__m81_inline int
__m81_u(__isnanl)(long double __value) __attribute__ ((__const__));
__m81_inline int
__m81_u(__isnanl)(long double __value)
{
  char __result;
  __asm("ftst%.x %1\n"
	"fsun %0" : "=dm" (__result) : "f" (__value));
  return __result;
}

#endif	/* GCC.  */
