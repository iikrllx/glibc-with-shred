/* Test exception in current environment.
   Copyright (C) 1997 Free Software Foundation, Inc.
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

#include <fenv_libc.h>

int
fetestexcept (int excepts)
{
  fenv_union_t u;
  int flags;

  /* Get the current state.  */
  u.fenv = fegetenv_register ();

  /* Find the bits that indicate exceptions have occurred.  */
  flags = u.l[1] & FPSCR_STICKY_BITS;

  /* Set the FE_INVALID bit if any of the FE_INVALID_* bits are set.  */
  flags |= ((u.l[1] & FE_ALL_INVALID) != 0) << 31-24;

  return flags & excepts;
}
