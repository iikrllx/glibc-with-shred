/* Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef _SYS_USER_H
#define _SYS_USER_H	1

/* The whole purpose of this file is for GDB and GDB only.  Don't read
   too much into it.  Don't use it for anything other than GDB unless
   you know what you are doing.  */

struct user_fpregs_struct
{
  unsigned short int cwd;
  unsigned short int swd;
  unsigned short int twd;
  unsigned short int fop;
  unsigned int fip;
  unsigned int fcs;
  unsigned int foo;
  unsigned int fos;
  unsigned int mxcsr;
  unsigned int reserved;
  unsigned int st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
  unsigned int xmm_space[32];  /* 8*16 bytes for each XMM-reg = 128 bytes */
  unsigned int padding[56];
};

struct user_regs_struct
{
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
  unsigned long fs_base;
  unsigned long kernel_gs_base;
};

struct user
{
  struct user_regs_struct	regs;
  int				u_fpvalid;
  struct user_fpregs_struct	i387;
  unsigned long int		u_tsize;
  unsigned long int		u_dsize;
  unsigned long int		u_ssize;
  unsigned long			start_code;
  unsigned long			start_stack;
  long int			signal;
  int				reserved;
  struct user_regs_struct*	u_ar0;
  struct user_fpregs_struct*	u_fpstate;
  unsigned long int		magic;
  char				u_comm [32];
  int				u_debugreg [8];
};

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))
#define NBPG			PAGE_SIZE
#define UPAGES			1
#define HOST_TEXT_START_ADDR	(u.start_code)
#define HOST_STACK_END_ADDR	(u.start_stack + u.u_ssize * NBPG)

#endif	/* _SYS_USER_H */
