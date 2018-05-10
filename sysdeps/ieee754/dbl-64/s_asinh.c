/* @(#)s_asinh.c 5.1 93/09/24 */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/* asinh(x)
 * Method :
 *	Based on
 *		asinh(x) = sign(x) * log [ |x| + sqrt(x*x+1) ]
 *	we have
 *	asinh(x) := x  if  1+x*x=1,
 *		 := sign(x)*(log(x)+ln2)) for large |x|, else
 *		 := sign(x)*log(2|x|+1/(|x|+sqrt(x*x+1))) if|x|>2, else
 *		 := sign(x)*log1p(|x| + x^2/(1 + sqrt(1+x^2)))
 */

#include <float.h>
#include <math.h>
#include <math_private.h>
#include <math-underflow.h>
#include <libm-alias-double.h>

static const double
  one = 1.00000000000000000000e+00, /* 0x3FF00000, 0x00000000 */
  ln2 = 6.93147180559945286227e-01, /* 0x3FE62E42, 0xFEFA39EF */
  huge = 1.00000000000000000000e+300;

double
__asinh (double x)
{
  double w;
  int32_t hx, ix;
  GET_HIGH_WORD (hx, x);
  ix = hx & 0x7fffffff;
  if (__glibc_unlikely (ix < 0x3e300000))                  /* |x|<2**-28 */
    {
      math_check_force_underflow (x);
      if (huge + x > one)
	return x;                       /* return x inexact except 0 */
    }
  if (__glibc_unlikely (ix > 0x41b00000))                  /* |x| > 2**28 */
    {
      if (ix >= 0x7ff00000)
	return x + x;                           /* x is inf or NaN */
      w = __ieee754_log (fabs (x)) + ln2;
    }
  else
    {
      double xa = fabs (x);
      if (ix > 0x40000000)              /* 2**28 > |x| > 2.0 */
	{
	  w = __ieee754_log (2.0 * xa + one / (sqrt (xa * xa + one) +
              xa));
	}
      else                      /* 2.0 > |x| > 2**-28 */
	{
	  double t = xa * xa;
	  w = __log1p (xa + t / (one + sqrt (one + t)));
	}
    }
  return __copysign (w, x);
}
libm_alias_double (__asinh, asinh)
