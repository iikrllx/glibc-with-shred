/* Adapted for use as nearbyint by Ulrich Drepper <drepper@cygnus.com>.  */
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
 * rint(x)
 * Return x rounded to integral value according to the prevailing
 * rounding mode.
 * Method:
 *	Using floating addition.
 * Exception:
 *	Inexact flag raised if x not equal to rint(x).
 */

#include <fenv.h>
#include <math.h>
#include <math_private.h>

static const double
TWO52[2]={
  4.50359962737049600000e+15, /* 0x43300000, 0x00000000 */
 -4.50359962737049600000e+15, /* 0xC3300000, 0x00000000 */
};

double
__nearbyint(double x)
{
	fenv_t env;
	int64_t i0,sx;
	int32_t j0;
	EXTRACT_WORDS64(i0,x);
	sx = (i0>>63)&1;
	j0 = ((i0>>52)&0x7ff)-0x3ff;
	if(__builtin_expect(j0<52, 1)) {
	    if(j0<0) {
		libc_feholdexcept (&env);
		double w = TWO52[sx]+x;
		double t =  w-TWO52[sx];
		math_opt_barrier(t);
		libc_fesetenv (&env);
		return __copysign (t, x);
	    }
	} else {
	    if(j0==0x400) return x+x;	/* inf or NaN */
	    else return x;		/* x is integral */
	}
	libc_feholdexcept (&env);
	double w = TWO52[sx]+x;
	double t = w-TWO52[sx];
	math_opt_barrier (t);
	libc_fesetenv (&env);
	return t;
}
weak_alias (__nearbyint, nearbyint)
#ifdef NO_LONG_DOUBLE
strong_alias (__nearbyint, __nearbyintl)
weak_alias (__nearbyint, nearbyintl)
#endif
