/* Copyright (C) 1991, 1992, 1995 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <sysdeps/unix/sysdep.h>

#ifdef	ASSEMBLER

#ifdef	__STDC__
#define	ENTRY(name)							      \
  .globl _##name;							      \
  .even;								      \
  _##name##:
#else
#define	ENTRY(name)							      \
  .globl _/**/name;							      \
  .even;								      \
  _/**/name/**/:
#endif

#ifdef	__STDC__
#define	PSEUDO(name, syscall_name, args)				      \
  .even;								      \
  .globl syscall_error							      \
  error: jmp syscall_error;						      \
  ENTRY (name)								      \
  chmk $SYS_##syscall_name						      \
  bcs error
#else
#define	PSEUDO(name, syscall_name, args)				      \
  .even;								      \
  .globl syscall_error							      \
  error: jmp syscall_error;						      \
  ENTRY (name)								      \
  chmk $SYS_/**/syscall_name						      \
  bcs error
#endif

#define MOVE(x,y)	movl x , y

#endif	/* ASSEMBLER */
