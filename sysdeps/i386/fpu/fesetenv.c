/* Install given floating-point environment.
   Copyright (C) 1997-2015 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <fenv.h>
#include <assert.h>
#include <unistd.h>
#include <ldsodefs.h>
#include <dl-procinfo.h>


int
__fesetenv (const fenv_t *envp)
{
  fenv_t temp;

  /* The memory block used by fstenv/fldenv has a size of 28 bytes.  */
  assert (sizeof (fenv_t) == 28);

  /* Install the environment specified by ENVP.  But there are a few
     values which we do not want to come from the saved environment.
     Therefore, we get the current environment and replace the values
     we want to use from the environment specified by the parameter.  */
  __asm__ ("fnstenv %0" : "=m" (*&temp));

  if (envp == FE_DFL_ENV)
    {
      temp.__control_word |= FE_ALL_EXCEPT;
      temp.__control_word &= ~FE_TOWARDZERO;
      temp.__status_word &= ~FE_ALL_EXCEPT;
    }
  else if (envp == FE_NOMASK_ENV)
    {
      temp.__control_word &= ~(FE_ALL_EXCEPT | FE_TOWARDZERO);
      temp.__status_word &= ~FE_ALL_EXCEPT;
    }
  else
    {
      temp.__control_word &= ~(FE_ALL_EXCEPT | FE_TOWARDZERO);
      temp.__control_word |= (envp->__control_word
			      & (FE_ALL_EXCEPT | FE_TOWARDZERO));
      temp.__status_word &= ~FE_ALL_EXCEPT;
      temp.__status_word |= envp->__status_word & FE_ALL_EXCEPT;
    }
  temp.__eip = 0;
  temp.__cs_selector = 0;
  temp.__opcode = 0;
  temp.__data_offset = 0;
  temp.__data_selector = 0;

  __asm__ ("fldenv %0" : : "m" (temp));

  if ((GLRO(dl_hwcap) & HWCAP_I386_XMM) != 0)
    {
      unsigned int mxcsr;
      __asm__ ("stmxcsr %0" : "=m" (mxcsr));

      if (envp == FE_DFL_ENV)
	{
	  /* Set mask for SSE MXCSR.  */
	  mxcsr |= (FE_ALL_EXCEPT << 7);
	  /* Set rounding to FE_TONEAREST.  */
	  mxcsr &= ~0x6000;
	  mxcsr |= (FE_TONEAREST << 3);
	}
      else if (envp == FE_NOMASK_ENV)
	{
	  /* Do not mask exceptions.  */
	  mxcsr &= ~(FE_ALL_EXCEPT << 7);
	  /* Set rounding to FE_TONEAREST.  */
	  mxcsr &= ~0x6000;
	  mxcsr |= (FE_TONEAREST << 3);
	}
      else
	mxcsr = envp->__eip;

      __asm__ ("ldmxcsr %0" : : "m" (mxcsr));
    }

  /* Success.  */
  return 0;
}

#include <shlib-compat.h>
#if SHLIB_COMPAT (libm, GLIBC_2_1, GLIBC_2_2)
strong_alias (__fesetenv, __old_fesetenv)
compat_symbol (libm, __old_fesetenv, fesetenv, GLIBC_2_1);
#endif

libm_hidden_def (__fesetenv)
libm_hidden_ver (__fesetenv, fesetenv)
versioned_symbol (libm, __fesetenv, fesetenv, GLIBC_2_2);
