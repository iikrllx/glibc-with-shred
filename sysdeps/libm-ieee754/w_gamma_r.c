/* @(#)wr_gamma.c 5.1 93/09/24 */
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
static char rcsid[] = "$NetBSD: w_gamma_r.c,v 1.7 1995/11/20 22:06:45 jtc Exp $";
#endif

/*
 * wrapper double gamma_r(double x, int *signgamp)
 */

#include "math.h"
#include "math_private.h"


#ifdef __STDC__
	double __gamma_r(double x, int *signgamp) /* wrapper lgamma_r */
#else
	double __gamma_r(x,signgamp)              /* wrapper lgamma_r */
        double x; int *signgamp;
#endif
{
#ifdef _IEEE_LIBM
	return __ieee754_lgamma_r(x,signgamp);
#else
        double y;
        y = __ieee754_lgamma_r(x,signgamp);
        if(_LIB_VERSION == _IEEE_) return y;
        if(!__finite(y)&&__finite(x)) {
            if(__floor(x)==x&&x<=0.0)
                return __kernel_standard(x,x,41); /* gamma pole */
            else
                return __kernel_standard(x,x,40); /* gamma overflow */
        } else
            return y;
#endif
}
weak_alias (__gamma_r, gamma_r)
#ifdef NO_LONG_DOUBLE
strong_alias (__gamma_r, __gammal_r)
weak_alias (__gamma_r, gammal_r)
#endif
