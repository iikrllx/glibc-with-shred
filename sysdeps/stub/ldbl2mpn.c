/* Copyright (C) 1995, 1997 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "gmp.h"
#include "gmp-impl.h"

/* Convert a `long double' to a multi-precision integer representing the
   significand scaled up by the highest possible number of significant bits
   of fraction (LDBL_MANT_DIG), and an integral power of two (MPN frexpl). */

mp_size_t
__mpn_extract_long_double (mp_ptr res_ptr, mp_size_t size,
		      int *expt, int *is_neg,
		      double value)
{
#error "not implemented for this floating point format"
}
