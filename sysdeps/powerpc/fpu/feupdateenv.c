/* Install given floating-point environment and raise exceptions.
   Copyright (C) 1997, 1999, 2000 Free Software Foundation, Inc.
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

#include <fenv_libc.h>

int
__feupdateenv (const fenv_t *envp)
{
  fenv_union_t old, new;

  /* Save the currently set exceptions.  */
  new.fenv = *envp;
  old.fenv = fegetenv_register ();

  /* Copy the set exceptions from `old' to `new'.  */
  new.l[1] = (new.l[1] & 0xE00000FF) | (old.l[1] & 0x1FFFFF00);

  /* Atomically enable and raise (if appropriate) exceptions set in `new'. */
  fesetenv_register (new.fenv);

  /* Success.  */
  return 0;
}
strong_alias (__feupdateenv, __old_feupdateenv)
symbol_version (__old_feupdateenv, feupdateenv, GLIBC_2.1);
default_symbol_version (__feupdateenv, feupdateenv, GLIBC_2.2);
