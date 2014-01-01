/* Install given floating-point environment.
   Copyright (C) 2001-2014 Free Software Foundation, Inc.
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

#include <fenv.h>
#include <assert.h>


int
fesetenv (const fenv_t *envp)
{
  fenv_t temp;

  /* Install the environment specified by ENVP.  But there are a few
     values which we do not want to come from the saved environment.
     Therefore, we get the current environment and replace the values
     we want to use from the environment specified by the parameter.  */
  __asm__ ("fnstenv %0\n"
	   "stmxcsr %1" : "=m" (*&temp), "=m" (*&temp.__mxcsr));

  if (envp == FE_DFL_ENV)
    {
      temp.__control_word |= FE_ALL_EXCEPT;
      temp.__control_word &= ~FE_TOWARDZERO;
      temp.__status_word &= ~FE_ALL_EXCEPT;
      temp.__eip = 0;
      temp.__cs_selector = 0;
      temp.__opcode = 0;
      temp.__data_offset = 0;
      temp.__data_selector = 0;
      /* Set mask for SSE MXCSR.  */
      temp.__mxcsr |= (FE_ALL_EXCEPT << 7);
      /* Set rounding to FE_TONEAREST.  */
      temp.__mxcsr &= ~ 0x6000;
      temp.__mxcsr |= (FE_TONEAREST << 3);
    }
  else if (envp == FE_NOMASK_ENV)
    {
      temp.__control_word &= ~(FE_ALL_EXCEPT | FE_TOWARDZERO);
      temp.__status_word &= ~FE_ALL_EXCEPT;
      temp.__eip = 0;
      temp.__cs_selector = 0;
      temp.__opcode = 0;
      temp.__data_offset = 0;
      temp.__data_selector = 0;
      /* Set mask for SSE MXCSR.  */
      /* Set rounding to FE_TONEAREST.  */
      temp.__mxcsr &= ~ 0x6000;
      temp.__mxcsr |= (FE_TONEAREST << 3);
      /* Do not mask exceptions.  */
      temp.__mxcsr &= ~(FE_ALL_EXCEPT << 7);
    }
  else
    {
      temp.__control_word &= ~(FE_ALL_EXCEPT | FE_TOWARDZERO);
      temp.__control_word |= (envp->__control_word
			      & (FE_ALL_EXCEPT | FE_TOWARDZERO));
      temp.__status_word &= ~FE_ALL_EXCEPT;
      temp.__status_word |= envp->__status_word & FE_ALL_EXCEPT;
      temp.__eip = envp->__eip;
      temp.__cs_selector = envp->__cs_selector;
      temp.__opcode = envp->__opcode;
      temp.__data_offset = envp->__data_offset;
      temp.__data_selector = envp->__data_selector;
      temp.__mxcsr = envp->__mxcsr;
    }

  __asm__ ("fldenv %0\n"
	   "ldmxcsr %1" : : "m" (temp), "m" (temp.__mxcsr));

  /* Success.  */
  return 0;
}
libm_hidden_def (fesetenv)
