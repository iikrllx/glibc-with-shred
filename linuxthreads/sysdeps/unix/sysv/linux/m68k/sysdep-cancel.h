/* Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Schwab <schwab@suse.de>, 2002.

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
#ifndef __ASSEMBLER__
# include <linuxthreads/internals.h>
#endif

#if !defined NOT_IN_libc || defined IS_IN_libpthread

# undef PSEUDO
# define PSEUDO(name, syscall_name, args)				      \
  .text;								      \
  ENTRY (name)								      \
    SINGLE_THREAD_P;							      \
    jne .Lpseudo_cancel;						      \
    DO_CALL (syscall_name, args);					      \
    cmp.l &-4095, %d0;							      \
    jcc SYSCALL_ERROR_LABEL;						      \
    rts;								      \
  .Lpseudo_cancel:							      \
    CENABLE;								      \
    DOCARGS_##args							      \
    move.l %d0, -(%sp);							      \
    move.l &SYS_ify (syscall_name), %d0;				      \
    trap &0;								      \
    move.l %d0, %d2;							      \
    CDISABLE;								      \
    addq.l &4, %sp;							      \
    move.l %d2, %d0;							      \
    UNDOCARGS_##args							      \
    cmp.l &-4095, %d0;							      \
    jcc SYSCALL_ERROR_LABEL

# define DOCARGS_0	move.l %d2, -(%sp);
# define _DOCARGS_0(n)
# define UNDOCARGS_0	move.l (%sp)+, %d2;

# define DOCARGS_1	_DOCARGS_1 (4); DOCARGS_0
# define _DOCARGS_1(n)	move.l n(%sp), %d1; _DOARGS_0 (n)
# define UNDOCARGS_1	UNDOCARGS_0

# define DOCARGS_2	_DOCARGS_2 (8)
# define _DOCARGS_2(n)	move.l %d2, -(%sp); move.l n+4(%sp), %d2;	\
			_DOCARGS_1 (n)
# define UNDOCARGS_2	UNDOCARGS_1

# define DOCARGS_3	_DOCARGS_3 (12)
# define _DOCARGS_3(n)	move.l %d3, -(%sp); move.l n+4(%sp), %d3;	\
  	 		_DOCARGS_2 (n)
# define UNDOCARGS_3	UNDOCARGS_2; move.l (%sp)+, %d3;

# define DOCARGS_4	_DOCARGS_4 (16)
# define _DOCARGS_4(n)	move.l %d4, -(%sp); move.l n+4(%sp), %d4;	\
			_DOCARGS_3 (n)
# define UNDOCARGS_4	UNDOCARGS_3; move.l (%sp)+, %d4;

# define DOCARGS_5	_DOCARGS_5 (20)
# define _DOCARGS_5(n)	move.l %d5, -(%sp); move.l n+4(%sp), %d5;	\
			_DOCARGS_4 (n)
# define UNDOCARGS_5	UNDOCARGS_4; move.l (%sp)+, %d5;

# ifdef IS_IN_libpthread
#  define CENABLE	jbsr __pthread_enable_asynccancel
#  define CDISABLE	jbsr __pthread_disable_asynccancel
# else
#  define CENABLE	jbsr __libc_enable_asynccancel
#  define CDISABLE	jbsr __libc_disable_asynccancel
# endif

# if !defined NOT_IN_libc
#  define __local_multiple_threads __libc_multiple_threads
# else
#  define __local_multiple_threads __pthread_multiple_threads
# endif

# ifndef __ASSEMBLER__
extern int __local_multiple_threads attribute_hidden;
#  define SINGLE_THREAD_P __builtin_expect (__local_multiple_threads == 0, 1)
# else
#  if !defined PIC
#   define SINGLE_THREAD_P tst.l __local_multiple_threads
#  else
#   if !defined HAVE_HIDDEN || !USE___THREAD
#    define SINGLE_THREAD_P \
  tst.l (__local_multiple_threads@GOTPC, %pc)
#   else
#    define SINGLE_THREAD_P \
  tst.l  (__local_multiple_threads@GOTPC, %pc)
#   endif
#  endif
# endif

#elif !defined __ASSEMBLER__

/* This code should never be used but we define it anyhow.  */
# define SINGLE_THREAD_P (1)

#endif
