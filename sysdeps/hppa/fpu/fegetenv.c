/* Store current floating-point environment.
   Copyright (C) 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by David Huggins-Daines <dhd@debian.org>, 2000

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
fegetenv (fenv_t *envp)
{
  __asm__ (
	   "fstd %%fr0,0(%2)\n"
	   "fstd,ma %%fr1,8(%2)\n"
	   "fstd,ma %%fr2,8(%2)\n"
	   "fstd %%fr3,0(%2)\n"
	   : "=m" (*envp), "=r" (envp) : "1" (envp));
  return 0;
}
