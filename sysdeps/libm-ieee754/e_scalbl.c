/* e_scalbl.c -- long double version of s_scalb.c.
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

/*
 * __ieee754_scalbl(x, fn) is provide for
 * passing various standard test suite. One
 * should use scalbnl() instead.
 */

#include "math.h"
#include "math_private.h"

#ifdef _SCALB_INT
#ifdef __STDC__
	long double __ieee754_scalbl(long double x, int fn)
#else
	long double __ieee754_scalbl(x,fn)
	long double x; int fn;
#endif
#else
#ifdef __STDC__
	long double __ieee754_scalbl(long double x, long double fn)
#else
	long double __ieee754_scalbl(x,fn)
	long double x, fn;
#endif
#endif
{
#ifdef _SCALB_INT
	return scalbnl(x,fn);
#else
	if (isnanl(x)||isnanl(fn)) return x*fn;
	if (!finitel(fn)) {
	    if(fn>0.0) return x*fn;
	    else       return x/(-fn);
	}
	if (rintl(fn)!=fn) return (fn-fn)/(fn-fn);
	if ( fn > 65000.0) return scalbnl(x, 65000);
	if (-fn > 65000.0) return scalbnl(x,-65000);
	return scalbnl(x,(int)fn);
#endif
}
