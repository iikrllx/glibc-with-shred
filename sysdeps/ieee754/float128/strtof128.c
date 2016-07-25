/* strtof128 wrapper of strtof128_l.
   Copyright (C) 2017 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

/* The actual implementation for all floating point sizes is in strtod.c.
   These macros tell it to produce the `_Float128' version, `strtof128'.  */

#define FLOAT		_Float128
#define FLT		FLT128
#ifdef USE_WIDE_CHAR
# define STRTOF		wcstof128
# define STRTOF_L	__wcstof128_l
#else
# define STRTOF		strtof128
# define STRTOF_L	__strtof128_l
#endif

#include <float128_private.h>

#include <stdlib/strtod.c>
