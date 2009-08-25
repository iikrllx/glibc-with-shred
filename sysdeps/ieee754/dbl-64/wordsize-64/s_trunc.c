/* Truncate argument to nearest integral value not larger than the argument.
   Copyright (C) 1997, 1998, 2009 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <math.h>

#include "math_private.h"


double
__trunc (double x)
{
  int64_t i0, j0;
  int64_t sx;

  EXTRACT_WORDS64 (i0, x);
  sx = i0 & UINT64_C(0x8000000000000000);
  j0 = ((i0 >> 52) & 0x7ff) - 0x3ff;
  if (j0 < 52)
    {
      if (j0 < 0)
	/* The magnitude of the number is < 1 so the result is +-0.  */
	INSERT_WORDS64 (x, sx);
      else
	INSERT_WORDS64 (x, sx | (i0 & ~(UINT64_C(0x000fffffffffffff) >> j0)));
    }
  else
    {
      if (j0 == 0x400)
	/* x is inf or NaN.  */
	return x + x;
    }

  return x;
}
weak_alias (__trunc, trunc)
#ifdef NO_LONG_DOUBLE
strong_alias (__trunc, __truncl)
weak_alias (__trunc, truncl)
#endif
