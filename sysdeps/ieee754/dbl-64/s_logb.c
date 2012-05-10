/* @(#)s_logb.c 5.1 93/09/24 */
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

/*
 * double logb(x)
 * IEEE 754 logb. Included to pass IEEE test suite. Not recommend.
 * Use ilogb instead.
 */

#include <math.h>
#include <math_private.h>

double
__logb (double x)
{
  int32_t lx, ix, rix;

  EXTRACT_WORDS (ix, lx, x);
  ix &= 0x7fffffff;		/* high |x| */
  if ((ix | lx) == 0)
    return -1.0 / fabs (x);
  if (ix >= 0x7ff00000)
    return x * x;
  if (__builtin_expect ((rix = ix >> 20) == 0, 0))
    {
      /* POSIX specifies that denormal number is treated as
         though it were normalized.  */
      int m1 = (ix == 0) ? 0 : __builtin_clz (ix);
      int m2 = (lx == 0) ? 0 : __builtin_clz (lx);
      int ma = (m1 == 0) ? m2 + 32 : m1;
      return -1022.0 + (double)(11 - ma);
    }
  return (double) (rix - 1023);
}
weak_alias (__logb, logb)
#ifdef NO_LONG_DOUBLE
strong_alias (__logb, __logbl) weak_alias (__logb, logbl)
#endif
