/* Copyright (C) 1999-2016 Free Software Foundation, Inc.
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
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

#define __WORDSIZE	64
#define __WORDSIZE_TIME64_COMPAT32	0

#if !defined __NO_LONG_DOUBLE_MATH && !defined __LONG_DOUBLE_MATH_OPTIONAL

/* Signal that we didn't used to have a `long double'. The changes all
   the `long double' function variants to be redirects to the double
   functions.  */
# define __LONG_DOUBLE_MATH_OPTIONAL	1
# ifndef __LONG_DOUBLE_128__
#  define __NO_LONG_DOUBLE_MATH		1
# endif
#endif
