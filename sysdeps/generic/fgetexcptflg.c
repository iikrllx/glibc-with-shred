/* Store current representation for exceptions.
   Copyright (C) 1997, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

int
__fegetexceptflag (fexcept_t *flagp, int excepts)
{
  /* This always fails.  */
  return 1;
}
strong_alias (__fegetexceptflag, __old_fegetexceptflag)
symbol_version (__old_fegetexceptflag, fegetexceptflag, GLIBC_2.1);
default_symbol_version (__fegetexceptflag, fegetexceptflag, GLIBC_2.1.3);

stub_warning (fegetexceptflag)
#include <stub-tag.h>
