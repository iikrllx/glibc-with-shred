/* Raise given exceptions.
   Copyright (C) 1997, 1999 Free Software Foundation, Inc.
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

#include <fenv.h>
#include <math.h>

int
__feraiseexcept (int excepts)
{
  static volatile double sink;
  static const struct {
    double zero, one, max, min, sixteen, pi;
  } c = {
    0.0, 1.0, DBL_MAX, DBL_MIN, 16.0, M_PI
  };

  /* Raise exceptions represented by EXPECTS.  But we must raise only
     one signal at a time.  It is important the if the overflow/underflow
     exception and the inexact exception are given at the same time,
     the overflow/underflow exception follows the inexact exception.  */

  /* First: invalid exception.  */
  if ((FE_INVALID & excepts) != 0)
    /* One example of a invalid operation is 0/0.  */
    sink = c.zero / c.zero;

  /* Next: division by zero.  */
  if ((FE_DIVBYZERO & excepts) != 0)
    sink = c.one / c.zero;

  /* Next: overflow.  */
  if ((FE_OVERFLOW & excepts) != 0)
    sink = c.max * c.max;

  /* Next: underflow.  */
  if ((FE_UNDERFLOW & excepts) != 0)
    sink = c.min / c.sixteen;

  /* Last: inexact.  */
  if ((FE_INEXACT & excepts) != 0)
    sink = c.one / c.pi;

  /* Success.  */
  return 0;
}
strong_alias (__feraiseexcept, __old_feraiseexcept)
symbol_version (__old_feraiseexcept, feraiseexcept, GLIBC_2.1);
default_symbol_version (__feraiseexcept, feraiseexcept, GLIBC_2.1.3);
