/* Copyright (C) 1992, 93, 95-99, 2000 Free Software Foundation,
   Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper, <drepper@gnu.ai.mit.edu>, August 1995.
   Changed by Kaz Kojima, <kkojima@rr.iij4u.or.jp>.

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

#ifndef _LINUX_SH_SYSDEP_H
#define _LINUX_SH_SYSDEP_H 1

/* There is some commonality.  */
#include <sysdeps/unix/sh/sysdep.h>

/* For Linux we can use the system call table in the header file
	/usr/include/asm/unistd.h
   of the kernel.  But these symbols do not follow the SYS_* syntax
   so we have to redefine the `SYS_ify' macro here.  */
#undef SYS_ify
#define SYS_ify(syscall_name)	(__NR_##syscall_name)


#ifdef __ASSEMBLER__

/* Linux uses a negative return value to indicate syscall errors,
   unlike most Unices, which use the condition codes' carry flag.

   Since version 2.1 the return value of a system call might be
   negative even if the call succeeded.  E.g., the `lseek' system call
   might return a large offset.  Therefore we must not anymore test
   for < 0, but test for a real error by making sure the value in R0
   is a real error number.  Linus said he will make sure the no syscall
   returns a value in -1 .. -4095 as a valid result so we can savely
   test with -4095.  */

#define _IMM12 #-12
#undef	PSEUDO
#ifdef SHARED
#define	PSEUDO(name, syscall_name, args) \
 .text; \
 ENTRY (name); \
    DO_CALL (args, syscall_name); \
    mov r0,r1; \
    mov _IMM12,r2; \
    shad r2,r1; \
    not r1,r1; \
    tst r1,r1; \
    bf 1f; \
    mov r0,r4; \
    mov.l r12,@-r15; \
    sts.l pr,@-r15; \
    mov.l 0f,r12; \
    mova 0f,r0; \
    add r0,r12; \
    mov.l 2f,r1; \
    mova 2f,r0; \
    add r0,r1; \
    jsr @r1; \
     nop; \
    lds.l @r15+,pr; \
    rts; \
     mov.l @r15+,r12; \
    .align 2; \
 2: .long PLTJMP(C_SYMBOL_NAME(__syscall_error)); \
 0: .long _GLOBAL_OFFSET_TABLE_; \
 1:
#else
#define	PSEUDO(name, syscall_name, args) \
 .text; \
 ENTRY (name); \
    DO_CALL (args, syscall_name); \
    mov r0,r1; \
    mov _IMM12,r2; \
    shad r2,r1; \
    not r1,r1; \
    tst r1,r1; \
    bf 1f; \
    mov.l 2f,r1; \
    jmp @r1; \
     mov r0, r4; \
    .align 2; \
 2: .long PLTJMP(C_SYMBOL_NAME(__syscall_error)); \
 1:
#endif

#undef	PSEUDO_END
#define	PSEUDO_END(name) \
  SYSCALL_ERROR_HANDLER \
  END (name)

#define SYSCALL_ERROR_HANDLER	/* Nothing here; code in sysdep.S is used.  */

#define SYSCALL_INST0	trapa #0
#define SYSCALL_INST1	trapa #0
#define SYSCALL_INST2	trapa #0
#define SYSCALL_INST3	trapa #0
#define SYSCALL_INST4	trapa #0
#define SYSCALL_INST5	trapa #1
#define SYSCALL_INST6	trapa #2

#undef	DO_CALL
#define DO_CALL(args, syscall_name) \
    mov.l 1f,r0; \
    SYSCALL_INST##args;	\
    bra 2f; \
     nop; \
    .align 2; \
 1: .long SYS_ify(syscall_name); \
 2:

#else /* not __ASSEMBLER__ */

#undef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...) \
  __syscall_##name(args)

#endif	/* __ASSEMBLER__ */

#endif /* linux/sh/sysdep.h */
