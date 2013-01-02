/* Round argument to nearest integral value according to current rounding
   direction.
   Copyright (C) 1997-2013 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <math.h>

#include <math_private.h>

static const double two52[2] =
{
  4.50359962737049600000e+15, /* 0x43300000, 0x00000000 */
 -4.50359962737049600000e+15, /* 0xC3300000, 0x00000000 */
};


long int
__lrint (double x)
{
  int32_t j0;
  u_int32_t i0,i1;
  volatile double w;
  double t;
  long int result;
  int sx;

  EXTRACT_WORDS (i0, i1, x);
  j0 = ((i0 >> 20) & 0x7ff) - 0x3ff;
  sx = i0 >> 31;
  i0 &= 0xfffff;
  i0 |= 0x100000;

  if (j0 < 20)
    {
      w = two52[sx] + x;
      t = w - two52[sx];
      EXTRACT_WORDS (i0, i1, t);
      j0 = ((i0 >> 20) & 0x7ff) - 0x3ff;
      i0 &= 0xfffff;
      i0 |= 0x100000;

      result = (j0 < 0 ? 0 : i0 >> (20 - j0));
    }
  else if (j0 < (int32_t) (8 * sizeof (long int)) - 1)
    {
      if (j0 >= 52)
	result = ((long int) i0 << (j0 - 20)) | (i1 << (j0 - 52));
      else
	{
	  w = two52[sx] + x;
	  t = w - two52[sx];
	  EXTRACT_WORDS (i0, i1, t);
	  j0 = ((i0 >> 20) & 0x7ff) - 0x3ff;
	  i0 &= 0xfffff;
	  i0 |= 0x100000;

	  if (j0 == 20)
	    result = (long int) i0;
	  else
	    result = ((long int) i0 << (j0 - 20)) | (i1 >> (52 - j0));
	}
    }
  else
    {
      /* The number is too large.  It is left implementation defined
	 what happens.  */
      return (long int) x;
    }

  return sx ? -result : result;
}

weak_alias (__lrint, lrint)
#ifdef NO_LONG_DOUBLE
strong_alias (__lrint, __lrintl)
weak_alias (__lrint, lrintl)
#endif
