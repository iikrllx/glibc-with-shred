/* Header file for constants used in floating point <-> decimal conversions.
Copyright (C) 1995 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifndef _FPIOCONST_H
#define	_FPIOCONST_H

#include <float.h>
#include "gmp.h"


/* These values are used by __printf_fp, where they are noncritical (if the
   value is not large enough, it will just be slower); and by
   strtof/strtod/strtold, where it is critical (it's used for overflow
   detection).

   XXX These should be defined in <float.h>.  For the time being, we have the
   IEEE754 values here.  */

#define LDBL_MAX_10_EXP_LOG	12 /* = floor(log_2(LDBL_MAX_10_EXP)) */
#define DBL_MAX_10_EXP_LOG	8 /* = floor(log_2(DBL_MAX_10_EXP)) */
#define FLT_MAX_10_EXP_LOG	5 /* = floor(log_2(FLT_MAX_10_EXP)) */


/* Table of powers of ten.  This is used by __printf_fp and by
   strtof/strtod/strtold.  */
struct mp_power
  {
    const mp_limb *array;	/* The array with the number representation. */
    mp_size_t arraysize;	/* Size of the array.  */
    int p_expo;			/* Exponent of the number 10^(2^i).  */
    int m_expo;			/* Exponent of the number 10^-(2^i-1).  */
  };
extern const struct mp_power _fpioconst_pow10[LDBL_MAX_10_EXP_LOG + 1];


#endif	/* fpioconst.h */
