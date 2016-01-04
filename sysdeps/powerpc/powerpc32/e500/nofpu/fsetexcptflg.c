/* Set floating-point environment exception handling.  e500 version.
   Copyright (C) 1997-2016 Free Software Foundation, Inc.
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

#include <fenv_libc.h>

int
__fesetexceptflag (const fexcept_t *flagp, int excepts)
{
  unsigned long old_spefscr, spefscr;
  fexcept_t flag;
  int excepts_spe = __fexcepts_to_spe (excepts);

  /* Get the current state.  */
  old_spefscr = fegetenv_register ();

  /* Ignore exceptions not listed in 'excepts'.  */
  flag = *flagp & excepts_spe;

  /* Replace the exception status */
  spefscr = (old_spefscr & ~excepts_spe) | flag;

  /* Store the new status word (along with the rest of the environment).  */
  fesetenv_register (spefscr);

  /* If the state of the "invalid" or "underflow" flag has changed,
     inform the kernel.  */
  if (((spefscr ^ old_spefscr) & (SPEFSCR_FINVS | SPEFSCR_FUNFS)) != 0)
    __fe_note_change ();

  /* Success.  */
  return 0;
}

#include <shlib-compat.h>
#if SHLIB_COMPAT (libm, GLIBC_2_1, GLIBC_2_2)
strong_alias (__fesetexceptflag, __old_fesetexceptflag)
compat_symbol (libm, __old_fesetexceptflag, fesetexceptflag, GLIBC_2_1);
#endif

versioned_symbol (libm, __fesetexceptflag, fesetexceptflag, GLIBC_2_2);
