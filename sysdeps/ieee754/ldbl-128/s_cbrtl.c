/*							cbrtl.c
 *
 *	Cube root, long double precision
 *
 *
 *
 * SYNOPSIS:
 *
 * long double x, y, cbrtl();
 *
 * y = cbrtl( x );
 *
 *
 *
 * DESCRIPTION:
 *
 * Returns the cube root of the argument, which may be negative.
 *
 * Range reduction involves determining the power of 2 of
 * the argument.  A polynomial of degree 2 applied to the
 * mantissa, and multiplication by the cube root of 1, 2, or 4
 * approximates the root to within about 0.1%.  Then Newton's
 * iteration is used three times to converge to an accurate
 * result.
 *
 *
 *
 * ACCURACY:
 *
 *                      Relative error:
 * arithmetic   domain     # trials      peak         rms
 *    IEEE       -8,8       100000      1.3e-34     3.9e-35
 *    IEEE    exp(+-707)    100000      1.3e-34     4.3e-35
 *
 */

/*
Cephes Math Library Release 2.2: January, 1991
Copyright 1984, 1991 by Stephen L. Moshier
Adapted for glibc October, 2001.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA */


#include "math.h"
#include "math_private.h"

static const long double CBRT2 = 1.259921049894873164767210607278228350570251L;
static const long double CBRT4 = 1.587401051968199474751705639272308260391493L;
static const long double CBRT2I = 0.7937005259840997373758528196361541301957467L;
static const long double CBRT4I = 0.6299605249474365823836053036391141752851257L;


long double
__cbrtl (long double x)
{
  int e, rem, sign;
  long double z;

  if (!__finitel (x))
    return x + x;

  if (x == 0)
    return (x);

  if (x > 0)
    sign = 1;
  else
    {
      sign = -1;
      x = -x;
    }

  z = x;
 /* extract power of 2, leaving mantissa between 0.5 and 1  */
  x = __frexpl (x, &e);

  /* Approximate cube root of number between .5 and 1,
     peak relative error = 1.2e-6  */
  x = ((((1.3584464340920900529734e-1L * x
	  - 6.3986917220457538402318e-1L) * x
	 + 1.2875551670318751538055e0L) * x
	- 1.4897083391357284957891e0L) * x
       + 1.3304961236013647092521e0L) * x + 3.7568280825958912391243e-1L;

  /* exponent divided by 3 */
  if (e >= 0)
    {
      rem = e;
      e /= 3;
      rem -= 3 * e;
      if (rem == 1)
	x *= CBRT2;
      else if (rem == 2)
	x *= CBRT4;
    }
  else
    {				/* argument less than 1 */
      e = -e;
      rem = e;
      e /= 3;
      rem -= 3 * e;
      if (rem == 1)
	x *= CBRT2I;
      else if (rem == 2)
	x *= CBRT4I;
      e = -e;
    }

  /* multiply by power of 2 */
  x = __ldexpl (x, e);

  /* Newton iteration */
  x -= (x - (z / (x * x))) * 0.3333333333333333333333333333333333333333L;
  x -= (x - (z / (x * x))) * 0.3333333333333333333333333333333333333333L;
  x -= (x - (z / (x * x))) * 0.3333333333333333333333333333333333333333L;

  if (sign < 0)
    x = -x;
  return (x);
}

weak_alias (__cbrtl, cbrtl)
