/* Copyright (C) 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Richard Henderson.

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

#include <math.h>


/* Use the -inf rounding mode conversion instructions to implement
   floor.  We note when the exponent is large enough that the value
   must be integral, as this avoids unpleasant integer overflows.  */

double
__floor (double x)
{
  /* Check not zero since floor(-0) == -0.  */
  if (x != 0 && fabs (x) < 9007199254740992.0)  /* 1 << DBL_MANT_DIG */
    {
      double __tmp1;
      __asm (
#ifdef _IEEE_FP_INEXACT
	     "cvttq/svim %2,%1\n\t"
#else
	     "cvttq/svm %2,%1\n\t"
#endif
	     "cvtqt/m %1,%0\n\t"
	     : "=f"(x), "=&f"(__tmp1)
	     : "f"(x));
    }
  return x;
}

weak_alias (__floor, floor)
#ifdef NO_LONG_DOUBLE
strong_alias (__floor, __floorl)
weak_alias (__floor, floorl)
#endif
