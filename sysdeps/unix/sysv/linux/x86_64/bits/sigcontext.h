/* Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _BITS_SIGCONTEXT_H
#define _BITS_SIGCONTEXT_H  1

#if !defined _SIGNAL_H && !defined _SYS_UCONTEXT_H
# error "Never use <bits/sigcontext.h> directly; include <signal.h> instead."
#endif

#include <bits/wordsize.h>

struct _fpreg
{
  unsigned short significand[4];
  unsigned short exponent;
};

struct _fpxreg
{
  unsigned short significand[4];
  unsigned short exponent;
  unsigned short padding[3];
};

struct _xmmreg
{
  __uint32_t	element[4];
};



#if __WORDSIZE == 32

struct _fpstate
{
  /* Regular FPU environment.  */
  __uint32_t	cw;
  __uint32_t		sw;
  __uint32_t		tag;
  __uint32_t		ipoff;
  __uint32_t		cssel;
  __uint32_t		dataoff;
  __uint32_t		datasel;
  struct _fpreg	_st[8];
  unsigned short status;
  unsigned short magic;

  /* FXSR FPU environment.  */
  __uint32_t		_fxsr_env[6];
  __uint32_t		mxcsr;
  __uint32_t		reserved;
  struct _fpxreg	_fxsr_st[8];
  struct _xmmreg 	_xmm[8];
  __uint32_t		padding[56];
};

struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
  unsigned long ebx;
  unsigned long edx;
  unsigned long ecx;
  unsigned long eax;
  unsigned long trapno;
  unsigned long err;
  unsigned long eip;
  unsigned short cs, __csh;
  unsigned long eflags;
  unsigned long esp_at_signal;
  unsigned short ss, __ssh;
  struct _fpstate * fpstate;
  unsigned long oldmask;
  unsigned long cr2;
};

#else

struct _fpstate
{
  /* FPU environment matching the 64-bit FXSAVE layout.  */
  __uint16_t		cwd;
  __uint16_t		swd;
  __uint16_t		ftw;
  __uint16_t		fop;
  __uint64_t		rip;
  __uint64_t		rdp;
  __uint32_t		mxcsr;
  __uint32_t		mxcr_mask;
  struct _fpxreg	_st[8];
  struct _xmmreg 	_xmm[16];
  __uint32_t		padding[24];
};

struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long r8;
  unsigned long r9;
  unsigned long r10;
  unsigned long r12;
  unsigned long r13;
  unsigned long r14;
  unsigned long r15;
  unsigned long rdi;
  unsigned long rsi;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long rdx;
  unsigned long rax;
  unsigned long trapno;
  unsigned long err;
  unsigned long rip;
  unsigned short cs, __csh;
  unsigned int __pad0;
  unsigned long eflags;
  unsigned long rsp_at_signal;
  struct _fpstate * fpstate;
  unsigned long oldmask;
  unsigned long cr2;
  unsigned long r11;
  unsigned long rcx;
  unsigned long rsp;
};

#endif

#endif /* _BITS_SIGCONTEXT_H */
