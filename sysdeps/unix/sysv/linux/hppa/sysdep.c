/* Copyright (C) 1997, 1998, 2001, 2003 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sysdep.h>
#include <errno.h>

extern int __syscall_error(int err_no);
extern int syscall (int sysnum, int arg0, int arg1, int arg2,
		    int arg3, int arg4, int arg5);

/* This routine is jumped to by all the syscall handlers, to stash
   an error number into errno.  */
int
__syscall_error (int err_no)
{
  __set_errno (err_no);
  return -1;
}


/* HPPA implements syscall() in 'C'; the assembler version would
   typically be in syscall.S. Also note that we have INLINE_SYSCALL,
   INTERNAL_SYSCALL, and all the generated pure assembly syscall wrappers.
   How often the function is used is unknown. */
int
syscall (int sysnum, int arg0, int arg1, int arg2, int arg3, int arg4,
	 int arg5)
{
  /* FIXME: Keep this matching INLINE_SYSCALL for hppa */
  long int __sys_res;
  {
    register unsigned long int __res asm("r28");
    LOAD_ARGS_6 (arg0, arg1, arg2, arg3, arg4, arg5)
    asm volatile (STW_ASM_PIC
		  "	ble  0x100(%%sr2, %%r0)	\n"
		  "	copy %1, %%r20		\n"
		  LDW_ASM_PIC
		  : "=r" (__res)
		  : "r" (sysnum) ASM_ARGS_6
		  : CALL_CLOB_REGS CLOB_ARGS_6);
    __sys_res = __res;
  }
  if ((unsigned long int) __sys_res >= (unsigned long int) -4095)
    {
      __set_errno (-__sys_res);
      __sys_res = -1;
    }
  return __sys_res;
}
