/* Compute cubic root of double value.
   Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Dirk Alboth <dirka@uni-paderborn.de> and
   Ulrich Drepper <drepper@cygnus.com>, 1997.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "math.h"
#include "math_private.h"


#define CBRT2 1.2599210498948731648		/* 2^(1/3) */
#define SQR_CBRT2 1.5874010519681994748		/* 2^(2/3) */

/* We don't use long double values here since U need not be computed
   with full precision.  */
static const double factor[5] =
{
  1.0 / SQR_CBRT2,
  1.0 / CBRT2,
  1.0,
  CBRT2,
  SQR_CBRT2
};


long double
__cbrtl (long double x)
{
  long double xm, ym, u, t2;
  int xe;

  /* Reduce X.  XM now is an range 1.0 to 0.5.  */
  xm = __frexpl (fabs (x), &xe);

  /* If X is not finite or is null return it (with raising exceptions
     if necessary.  */
  if (xe == 0)
    return x + x;

  u = (0.338058687610520237
       + (1.67595307700780102
	  + (-2.82414939754975962
	     + (4.09559907378707839 +
		(-4.11151425200350531
		 + (2.65298938441952296 +
		    (-0.988553671195413709
		     + 0.161617097923756032 * xm)
		    * xm)
		 * xm)
		* xm)
	     * xm)
	  * xm)
       *xm);

  t2 = u * u * u;

  ym = u * (t2 + 2.0 * xm) / (2.0 * t2 + xm) * factor[2 + xe % 3];

  return __ldexpl (x > 0.0 ? ym : -ym, xe / 3);
}
weak_alias (__cbrtl, cbrtl)
