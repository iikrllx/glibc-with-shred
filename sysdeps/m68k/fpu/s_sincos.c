/* Copyright (C) 1997 Free Software Foundation, Inc.
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

#define __LIBC_INTERNAL_MATH_INLINES
#include <math.h>

#ifndef FUNC
#define FUNC sincos
#endif
#ifndef float_type
#define float_type double
#endif

#define CONCATX(a,b) __CONCAT(a,b)

void
CONCATX(__,FUNC) (x, sinx, cosx)
     float_type x, *sinx, *cosx;
{
  __m81_u(CONCATX(__,FUNC))(x, sinx, cosx);
}

#define weak_aliasx(a,b) weak_alias(a,b)
weak_aliasx (CONCATX(__,FUNC), FUNC)
