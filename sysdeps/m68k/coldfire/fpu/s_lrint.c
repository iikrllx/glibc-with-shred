/* Copyright (C) 2006-2017 Free Software Foundation, Inc.
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

long int
__lrint (double x)
{
  long int result;
  asm ("fmove.l %1,%0" : "=dm" (result) : "f" (x));
  return result;
}
weak_alias (__lrint, lrint)
#ifdef NO_LONG_DOUBLE
strong_alias (__lrint, __lrintl)
weak_alias (__lrint, lrintl)
#endif
