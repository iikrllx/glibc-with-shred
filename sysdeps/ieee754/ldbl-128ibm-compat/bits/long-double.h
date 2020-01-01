/* Properties of long double type.  ldbl-opt version.
   Copyright (C) 2019-2020 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License  published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef __NO_LONG_DOUBLE_MATH
# define __LONG_DOUBLE_MATH_OPTIONAL	1
# ifndef __LONG_DOUBLE_128__
#  define __NO_LONG_DOUBLE_MATH		1
# endif
#endif
/* On platforms that reuse the _Float128 implementation for IEEE long
   double, access to the correct long double functions is selected based
   on the long double mode being used during the compilation.  On
   powerpc64le, this is true when -mabi=ieeelongdouble is in use.  */
#define __LONG_DOUBLE_USES_FLOAT128 (__LDBL_MANT_DIG__ == 113)
