/* s_tanhl.c -- long double version of s_tanh.c.
 * Conversion to long double by Ulrich Drepper,
 * Cygnus Support, drepper@cygnus.com.
 */

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

#if defined(LIBM_SCCS) && !defined(lint)
static char rcsid[] = "$NetBSD: $";
#endif

/* tanhl(x)
 * Return the Hyperbolic Tangent of x
 *
 * Method :
 *				        x    -x
 *				       e  - e
 *	0. tanhl(x) is defined to be -----------
 *				        x    -x
 *				       e  + e
 *	1. reduce x to non-negative by tanhl(-x) = -tanhl(x).
 *	2.  0      <= x <= 2**-55 : tanhl(x) := x*(one+x)
 *					         -t
 *	    2**-55 <  x <=  1     : tanhl(x) := -----; t = expm1l(-2x)
 *					        t + 2
 *						      2
 *	    1      <= x <=  23.0  : tanhl(x) := 1-  ----- ; t=expm1l(2x)
 *						    t + 2
 *	    23.0   <  x <= INF    : tanhl(x) := 1.
 *
 * Special cases:
 *	tanhl(NaN) is NaN;
 *	only tanhl(0)=0 is exact for finite argument.
 */

#include "math.h"
#include "math_private.h"

#ifdef __STDC__
static const long double one=1.0, two=2.0, tiny = 1.0e-4900L;
#else
static long double one=1.0, two=2.0, tiny = 1.0e-4900L;
#endif

#ifdef __STDC__
	long double __tanhl(long double x)
#else
	long double __tanhl(x)
	long double x;
#endif
{
	long double t,z;
	int32_t se;
	u_int32_t j0,j1,ix;

    /* High word of |x|. */
	GET_LDOUBLE_WORDS(se,j0,j1,x);
	ix = se&0x7fff;

    /* x is INF or NaN */
	if(ix==0x7fff) {
	    if (se>=0x7fff) return one/x+one;    /* tanhl(+-inf)=+-1 */
	    else            return one/x-one;    /* tanhl(NaN) = NaN */
	}

    /* |x| < 23 */
	if (ix < 0x4003 || (ix == 0x4003 && j0 < 0xb8000000u)) {/* |x|<23 */
	    if (ix<0x3fc8) 		/* |x|<2**-55 */
		return x*(one+x);    	/* tanh(small) = small */
	    if (ix>=0x3fff) {	/* |x|>=1  */
		t = __expm1l(two*fabsl(x));
		z = one - two/(t+two);
	    } else {
	        t = __expm1l(-two*fabsl(x));
	        z= -t/(t+two);
	    }
    /* |x| > 23, return +-1 */
	} else {
	    z = one - tiny;		/* raised inexact flag */
	}
	return (se>0x7fff)? -z: z;
}
weak_alias (__tanhl, tanhl)
