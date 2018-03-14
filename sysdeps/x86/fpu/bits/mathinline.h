/* Inline math functions for i387 and SSE.
   Copyright (C) 1995-2018 Free Software Foundation, Inc.
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

#ifndef _MATH_H
# error "Never use <bits/mathinline.h> directly; include <math.h> instead."
#endif

#ifndef __extern_always_inline
# define __MATH_INLINE __inline
#else
# define __MATH_INLINE __extern_always_inline
#endif

/* Disable x87 inlines when -fpmath=sse is passed and also when we're building
   on x86_64.  Older gcc (gcc-3.2 for example) does not define __SSE2_MATH__
   for x86_64.  */
#if !defined __SSE2_MATH__ && !defined __x86_64__
# if ((!defined __NO_MATH_INLINES || defined __LIBC_INTERNAL_MATH_INLINES) \
     && defined __OPTIMIZE__)

/* The inline functions do not set errno or raise necessarily the
   correct exceptions.  */
#  undef math_errhandling

/* A macro to define float, double, and long double versions of various
   math functions for the ix87 FPU.  FUNC is the function name (which will
   be suffixed with f and l for the float and long double version,
   respectively).  OP is the name of the FPU operation.
   We define two sets of macros.  The set with the additional NP
   doesn't add a prototype declaration.  */

#  ifdef __USE_ISOC99
#   define __inline_mathop(func, op) \
  __inline_mathop_ (double, func, op)					      \
  __inline_mathop_ (float, __CONCAT(func,f), op)			      \
  __inline_mathop_ (long double, __CONCAT(func,l), op)
#   define __inline_mathopNP(func, op) \
  __inline_mathopNP_ (double, func, op)					      \
  __inline_mathopNP_ (float, __CONCAT(func,f), op)			      \
  __inline_mathopNP_ (long double, __CONCAT(func,l), op)
#  else
#   define __inline_mathop(func, op) \
  __inline_mathop_ (double, func, op)
#   define __inline_mathopNP(func, op) \
  __inline_mathopNP_ (double, func, op)
#  endif

#  define __inline_mathop_(float_type, func, op) \
  __inline_mathop_decl_ (float_type, func, op, "0" (__x))
#  define __inline_mathopNP_(float_type, func, op) \
  __inline_mathop_declNP_ (float_type, func, op, "0" (__x))


#  ifdef __USE_ISOC99
#   define __inline_mathop_decl(func, op, params...) \
  __inline_mathop_decl_ (double, func, op, params)			      \
  __inline_mathop_decl_ (float, __CONCAT(func,f), op, params)		      \
  __inline_mathop_decl_ (long double, __CONCAT(func,l), op, params)
#   define __inline_mathop_declNP(func, op, params...) \
  __inline_mathop_declNP_ (double, func, op, params)			      \
  __inline_mathop_declNP_ (float, __CONCAT(func,f), op, params)		      \
  __inline_mathop_declNP_ (long double, __CONCAT(func,l), op, params)
#  else
#   define __inline_mathop_decl(func, op, params...) \
  __inline_mathop_decl_ (double, func, op, params)
#   define __inline_mathop_declNP(func, op, params...) \
  __inline_mathop_declNP_ (double, func, op, params)
#  endif

#  define __inline_mathop_decl_(float_type, func, op, params...) \
  __MATH_INLINE float_type func (float_type) __THROW;			      \
  __inline_mathop_declNP_ (float_type, func, op, params)

#  define __inline_mathop_declNP_(float_type, func, op, params...) \
  __MATH_INLINE float_type __NTH (func (float_type __x))		      \
  {									      \
    register float_type __result;					      \
    __asm __volatile__ (op : "=t" (__result) : params);			      \
    return __result;							      \
  }


#  ifdef __USE_ISOC99
#   define __inline_mathcode(func, arg, code) \
  __inline_mathcode_ (double, func, arg, code)				      \
  __inline_mathcode_ (float, __CONCAT(func,f), arg, code)		      \
  __inline_mathcode_ (long double, __CONCAT(func,l), arg, code)
#   define __inline_mathcodeNP(func, arg, code) \
  __inline_mathcodeNP_ (double, func, arg, code)			      \
  __inline_mathcodeNP_ (float, __CONCAT(func,f), arg, code)		      \
  __inline_mathcodeNP_ (long double, __CONCAT(func,l), arg, code)
#   define __inline_mathcode2(func, arg1, arg2, code) \
  __inline_mathcode2_ (double, func, arg1, arg2, code)			      \
  __inline_mathcode2_ (float, __CONCAT(func,f), arg1, arg2, code)	      \
  __inline_mathcode2_ (long double, __CONCAT(func,l), arg1, arg2, code)
#   define __inline_mathcodeNP2(func, arg1, arg2, code) \
  __inline_mathcodeNP2_ (double, func, arg1, arg2, code)		      \
  __inline_mathcodeNP2_ (float, __CONCAT(func,f), arg1, arg2, code)	      \
  __inline_mathcodeNP2_ (long double, __CONCAT(func,l), arg1, arg2, code)
#   define __inline_mathcode3(func, arg1, arg2, arg3, code) \
  __inline_mathcode3_ (double, func, arg1, arg2, arg3, code)		      \
  __inline_mathcode3_ (float, __CONCAT(func,f), arg1, arg2, arg3, code)	      \
  __inline_mathcode3_ (long double, __CONCAT(func,l), arg1, arg2, arg3, code)
#   define __inline_mathcodeNP3(func, arg1, arg2, arg3, code) \
  __inline_mathcodeNP3_ (double, func, arg1, arg2, arg3, code)		      \
  __inline_mathcodeNP3_ (float, __CONCAT(func,f), arg1, arg2, arg3, code)     \
  __inline_mathcodeNP3_ (long double, __CONCAT(func,l), arg1, arg2, arg3, code)
#  else
#   define __inline_mathcode(func, arg, code) \
  __inline_mathcode_ (double, func, (arg), code)
#   define __inline_mathcodeNP(func, arg, code) \
  __inline_mathcodeNP_ (double, func, (arg), code)
#   define __inline_mathcode2(func, arg1, arg2, code) \
  __inline_mathcode2_ (double, func, arg1, arg2, code)
#   define __inline_mathcodeNP2(func, arg1, arg2, code) \
  __inline_mathcodeNP2_ (double, func, arg1, arg2, code)
#   define __inline_mathcode3(func, arg1, arg2, arg3, code) \
  __inline_mathcode3_ (double, func, arg1, arg2, arg3, code)
#   define __inline_mathcodeNP3(func, arg1, arg2, arg3, code) \
  __inline_mathcodeNP3_ (double, func, arg1, arg2, arg3, code)
#  endif

#  define __inline_mathcode_(float_type, func, arg, code) \
  __MATH_INLINE float_type func (float_type) __THROW;			      \
  __inline_mathcodeNP_(float_type, func, arg, code)

#  define __inline_mathcodeNP_(float_type, func, arg, code) \
  __MATH_INLINE float_type __NTH (func (float_type arg))		      \
  {									      \
    code;								      \
  }


#  define __inline_mathcode2_(float_type, func, arg1, arg2, code) \
  __MATH_INLINE float_type func (float_type, float_type) __THROW;	      \
  __inline_mathcodeNP2_ (float_type, func, arg1, arg2, code)

#  define __inline_mathcodeNP2_(float_type, func, arg1, arg2, code) \
  __MATH_INLINE float_type __NTH (func (float_type arg1, float_type arg2))    \
  {									      \
    code;								      \
  }

#  define __inline_mathcode3_(float_type, func, arg1, arg2, arg3, code) \
  __MATH_INLINE float_type func (float_type, float_type, float_type) __THROW; \
  __inline_mathcodeNP3_(float_type, func, arg1, arg2, arg3, code)

#  define __inline_mathcodeNP3_(float_type, func, arg1, arg2, arg3, code) \
  __MATH_INLINE float_type __NTH (func (float_type arg1, float_type arg2,     \
					float_type arg3))		      \
  {									      \
    code;								      \
  }
# endif


# if !defined __NO_MATH_INLINES && defined __OPTIMIZE__
/* Miscellaneous functions  */

/* __FAST_MATH__ is defined by gcc -ffast-math.  */
#  ifdef __FAST_MATH__
#   ifdef __USE_GNU
#    define __sincos_code \
  register long double __cosr;						      \
  register long double __sinr;						      \
  register unsigned int __swtmp;					      \
  __asm __volatile__							      \
    ("fsincos\n\t"							      \
     "fnstsw	%w2\n\t"						      \
     "testl	$0x400, %2\n\t"						      \
     "jz	1f\n\t"							      \
     "fldpi\n\t"							      \
     "fadd	%%st(0)\n\t"						      \
     "fxch	%%st(1)\n\t"						      \
     "2: fprem1\n\t"							      \
     "fnstsw	%w2\n\t"						      \
     "testl	$0x400, %2\n\t"						      \
     "jnz	2b\n\t"							      \
     "fstp	%%st(1)\n\t"						      \
     "fsincos\n\t"							      \
     "1:"								      \
     : "=t" (__cosr), "=u" (__sinr), "=a" (__swtmp) : "0" (__x));	      \
  *__sinx = __sinr;							      \
  *__cosx = __cosr

__MATH_INLINE void
__NTH (__sincos (double __x, double *__sinx, double *__cosx))
{
  __sincos_code;
}

__MATH_INLINE void
__NTH (__sincosf (float __x, float *__sinx, float *__cosx))
{
  __sincos_code;
}

__MATH_INLINE void
__NTH (__sincosl (long double __x, long double *__sinx, long double *__cosx))
{
  __sincos_code;
}
#   endif


/* Optimized inline implementation, sometimes with reduced precision
   and/or argument range.  */

#   if __GNUC_PREREQ (3, 5)
#    define __expm1_code \
  register long double __temp;						      \
  __temp = __builtin_expm1l (__x);					      \
  return __temp ? __temp : __x
#   else
#    define __expm1_code \
  register long double __value;						      \
  register long double __exponent;					      \
  register long double __temp;						      \
  __asm __volatile__							      \
    ("fldl2e			# e^x - 1 = 2^(x * log2(e)) - 1\n\t"	      \
     "fmul	%%st(1)		# x * log2(e)\n\t"			      \
     "fst	%%st(1)\n\t"						      \
     "frndint			# int(x * log2(e))\n\t"			      \
     "fxch\n\t"								      \
     "fsub	%%st(1)		# fract(x * log2(e))\n\t"		      \
     "f2xm1			# 2^(fract(x * log2(e))) - 1\n\t"	      \
     "fscale			# 2^(x * log2(e)) - 2^(int(x * log2(e)))\n\t" \
     : "=t" (__value), "=u" (__exponent) : "0" (__x));			      \
  __asm __volatile__							      \
    ("fscale			# 2^int(x * log2(e))\n\t"		      \
     : "=t" (__temp) : "0" (1.0), "u" (__exponent));			      \
  __temp -= 1.0;							      \
  __temp += __value;							      \
  return __temp ? __temp : __x
#   endif
__inline_mathcodeNP_ (long double, __expm1l, __x, __expm1_code)

#   if __GNUC_PREREQ (3, 4)
__inline_mathcodeNP_ (long double, __expl, __x, return __builtin_expl (__x))
#   else
#    define __exp_code \
  register long double __value;						      \
  register long double __exponent;					      \
  __asm __volatile__							      \
    ("fldl2e			# e^x = 2^(x * log2(e))\n\t"		      \
     "fmul	%%st(1)		# x * log2(e)\n\t"			      \
     "fst	%%st(1)\n\t"						      \
     "frndint			# int(x * log2(e))\n\t"			      \
     "fxch\n\t"								      \
     "fsub	%%st(1)		# fract(x * log2(e))\n\t"		      \
     "f2xm1			# 2^(fract(x * log2(e))) - 1\n\t"	      \
     : "=t" (__value), "=u" (__exponent) : "0" (__x));			      \
  __value += 1.0;							      \
  __asm __volatile__							      \
    ("fscale"								      \
     : "=t" (__value) : "0" (__value), "u" (__exponent));		      \
  return __value
__inline_mathcodeNP (exp, __x, __exp_code)
__inline_mathcodeNP_ (long double, __expl, __x, __exp_code)
#   endif
#  endif /* __FAST_MATH__ */


#  if __GNUC_PREREQ (3, 4)
__inline_mathcodeNP2_ (long double, __atan2l, __y, __x,
		       return __builtin_atan2l (__y, __x))
#  else
#   define __atan2_code \
  register long double __value;						      \
  __asm __volatile__							      \
    ("fpatan"								      \
     : "=t" (__value) : "0" (__x), "u" (__y) : "st(1)");		      \
  return __value
#   ifdef __FAST_MATH__
__inline_mathcodeNP2 (atan2, __y, __x, __atan2_code)
#   endif
__inline_mathcodeNP2_ (long double, __atan2l, __y, __x, __atan2_code)
#  endif


#  ifdef __FAST_MATH__
#   if !__GNUC_PREREQ (3,3)
__inline_mathopNP (sqrt, "fsqrt")
__inline_mathopNP_ (long double, __sqrtl, "fsqrt")
#    define __libc_sqrtl(n) __sqrtl (n)
#   else
#    define __libc_sqrtl(n) __builtin_sqrtl (n)
#   endif
#  endif

#  if __GNUC_PREREQ (2, 8)
__inline_mathcodeNP_ (double, fabs, __x, return __builtin_fabs (__x))
#   ifdef __USE_ISOC99
__inline_mathcodeNP_ (float, fabsf, __x, return __builtin_fabsf (__x))
__inline_mathcodeNP_ (long double, fabsl, __x, return __builtin_fabsl (__x))
#   endif
__inline_mathcodeNP_ (long double, __fabsl, __x, return __builtin_fabsl (__x))
#  else
__inline_mathop (fabs, "fabs")
__inline_mathop_ (long double, __fabsl, "fabs")
# endif

__inline_mathcode_ (long double, __sgn1l, __x, \
  __extension__ union { long double __xld; unsigned int __xi[3]; } __n =      \
    { __xld: __x };							      \
  __n.__xi[2] = (__n.__xi[2] & 0x8000) | 0x3fff;			      \
  __n.__xi[1] = 0x80000000;						      \
  __n.__xi[0] = 0;							      \
  return __n.__xld)


#  ifdef __FAST_MATH__
/* The argument range of the inline version of sinhl is slightly reduced.  */
__inline_mathcodeNP (sinh, __x, \
  register long double __exm1 = __expm1l (__fabsl (__x));		      \
  return 0.5 * (__exm1 / (__exm1 + 1.0) + __exm1) * __sgn1l (__x))

__inline_mathcodeNP (cosh, __x, \
  register long double __ex = __expl (__x);				      \
  return 0.5 * (__ex + 1.0 / __ex))

__inline_mathcodeNP (tanh, __x, \
  register long double __exm1 = __expm1l (-__fabsl (__x + __x));	      \
  return __exm1 / (__exm1 + 2.0) * __sgn1l (-__x))
#  endif

__inline_mathcodeNP (floor, __x, \
  register long double __value;						      \
  register int __ignore;						      \
  unsigned short int __cw;						      \
  unsigned short int __cwtmp;						      \
  __asm __volatile ("fnstcw %3\n\t"					      \
		    "movzwl %3, %1\n\t"					      \
		    "andl $0xf3ff, %1\n\t"				      \
		    "orl $0x0400, %1\n\t"	/* rounding down */	      \
		    "movw %w1, %2\n\t"					      \
		    "fldcw %2\n\t"					      \
		    "frndint\n\t"					      \
		    "fldcw %3"						      \
		    : "=t" (__value), "=&q" (__ignore), "=m" (__cwtmp),	      \
		      "=m" (__cw)					      \
		    : "0" (__x));					      \
  return __value)

__inline_mathcodeNP (ceil, __x, \
  register long double __value;						      \
  register int __ignore;						      \
  unsigned short int __cw;						      \
  unsigned short int __cwtmp;						      \
  __asm __volatile ("fnstcw %3\n\t"					      \
		    "movzwl %3, %1\n\t"					      \
		    "andl $0xf3ff, %1\n\t"				      \
		    "orl $0x0800, %1\n\t"	/* rounding up */	      \
		    "movw %w1, %2\n\t"					      \
		    "fldcw %2\n\t"					      \
		    "frndint\n\t"					      \
		    "fldcw %3"						      \
		    : "=t" (__value), "=&q" (__ignore), "=m" (__cwtmp),	      \
		      "=m" (__cw)					      \
		    : "0" (__x));					      \
  return __value)

#  ifdef __FAST_MATH__
#   define __ldexp_code \
  register long double __value;						      \
  __asm __volatile__							      \
    ("fscale"								      \
     : "=t" (__value) : "0" (__x), "u" ((long double) __y));		      \
  return __value

__MATH_INLINE double
__NTH (ldexp (double __x, int __y))
{
  __ldexp_code;
}
#  endif


/* Optimized versions for some non-standardized functions.  */
#  ifdef __USE_ISOC99

#   ifdef __FAST_MATH__
__inline_mathcodeNP (expm1, __x, __expm1_code)

/* The argument range of the inline version of asinhl is slightly reduced.  */
__inline_mathcodeNP (asinh, __x, \
  register long double  __y = __fabsl (__x);				      \
  return (log1pl (__y * __y / (__libc_sqrtl (__y * __y + 1.0) + 1.0) + __y)   \
	  * __sgn1l (__x)))

__inline_mathcodeNP (acosh, __x, \
  return logl (__x + __libc_sqrtl (__x - 1.0) * __libc_sqrtl (__x + 1.0)))

__inline_mathcodeNP (atanh, __x, \
  register long double __y = __fabsl (__x);				      \
  return -0.5 * log1pl (-(__y + __y) / (1.0 + __y)) * __sgn1l (__x))

/* The argument range of the inline version of hypotl is slightly reduced.  */
__inline_mathcodeNP2 (hypot, __x, __y,
		      return __libc_sqrtl (__x * __x + __y * __y))

#   endif
#  endif

#  ifdef __USE_ISOC99
#   ifdef __FAST_MATH__

__MATH_INLINE float
__NTH (ldexpf (float __x, int __y))
{
  __ldexp_code;
}

__MATH_INLINE long double
__NTH (ldexpl (long double __x, int __y))
{
  __ldexp_code;
}

__inline_mathopNP (rint, "frndint")
#   endif /* __FAST_MATH__ */

#   define __lrint_code \
  long int __lrintres;							      \
  __asm__ __volatile__							      \
    ("fistpl %0"							      \
     : "=m" (__lrintres) : "t" (__x) : "st");				      \
  return __lrintres
__MATH_INLINE long int
__NTH (lrintf (float __x))
{
  __lrint_code;
}
__MATH_INLINE long int
__NTH (lrint (double __x))
{
  __lrint_code;
}
__MATH_INLINE long int
__NTH (lrintl (long double __x))
{
  __lrint_code;
}
#   undef __lrint_code

#   define __llrint_code \
  long long int __llrintres;						      \
  __asm__ __volatile__							      \
    ("fistpll %0"							      \
     : "=m" (__llrintres) : "t" (__x) : "st");				      \
  return __llrintres
__extension__
__MATH_INLINE long long int
__NTH (llrintf (float __x))
{
  __llrint_code;
}
__extension__
__MATH_INLINE long long int
__NTH (llrint (double __x))
{
  __llrint_code;
}
__extension__
__MATH_INLINE long long int
__NTH (llrintl (long double __x))
{
  __llrint_code;
}
#   undef __llrint_code

# endif


#  ifdef __USE_MISC

/* This function is used in the `isfinite' macro.  */
__MATH_INLINE int
__NTH (__finite (double __x))
{
  return (__extension__
	  (((((union { double __d; int __i[2]; }) {__d: __x}).__i[1]
	     | 0x800fffffu) + 1) >> 31));
}

#  endif /* __USE_MISC  */

/* Undefine some of the large macros which are not used anymore.  */
#  undef __atan2_code
#  ifdef __FAST_MATH__
#   undef __expm1_code
#   undef __exp_code
#   undef __sincos_code
#  endif /* __FAST_MATH__ */

# endif /* __NO_MATH_INLINES  */


/* This code is used internally in the GNU libc.  */
# ifdef __LIBC_INTERNAL_MATH_INLINES
__inline_mathop (__ieee754_sqrt, "fsqrt")
__inline_mathcode2_ (long double, __ieee754_atan2l, __y, __x,
		     register long double __value;
		     __asm __volatile__ ("fpatan\n\t"
					 : "=t" (__value)
					 : "0" (__x), "u" (__y) : "st(1)");
		     return __value;)
# endif

#endif /* !__SSE2_MATH__ && !__x86_64__ */
