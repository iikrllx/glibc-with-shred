/* Set flags signalling availability of kernel features based on given
   kernel version number.
   Copyright (C) 1999 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* This file must not contain any C code.  At least it must be protected
   to allow using the file also in assembler files.  */

/* XXX For testing.  */
#define __LINUX_KERNEL_VERSION 131584

#ifndef __LINUX_KERNEL_VERSION
/* We assume the worst; all kernels should be supported.  */
# define __LINUX_KERNEL_VERSION	0
#endif

/* We assume for __LINUX_KERNEL_VERSION the same encoding used in
   linux/version.h.  I.e., the major, minor, and subminor all get a
   byte with the major number being in the highest byte.  This means
   we can do numeric comparisons.

   In the following we will define certain symbols depending on
   whether the describes kernel feature is available in the kernel
   version given by __LINUX_KERNEL_VERSION.  We are not always exactly
   recording the correct versions in which the features were
   introduced.  If somebody cares these values can afterwards be
   corrected.  Most of the numbers here are set corresponding to
   2.2.0.  */

/* `getcwd' system call.  */
#if __LINUX_KERNEL_VERSION >= 131584
# define __ASSUME_GETCWD_SYSCALL	1
#endif

/* Real-time signal became usable in 2.1.70.  */
#if __LINUX_KERNEL_VERSION >= 131398
# define __ASSUME_REALTIME_SIGNALS	1
#endif

/* When were the `pread'/`pwrite' syscalls introduced?  */
#if __LINUX_KERNEL_VERSION >= 131584
# define __ASSUME_PREAD_SYSCALL		1
# define __ASSUME_PWRITE_SYSCALL	1
#endif

/* When was `poll' introduced?  */
#if __LINUX_KERNEL_VERSION >= 131584
# define __ASSUME_POLL_SYSCALL		1
#endif

/* The `lchown' syscall was introduced in 2.1.80.  */
#if __LINUX_KERNEL_VERSION >= 131408
# define __ASSUME_LCHOWN_SYSCALL	1
#endif

/* When did the `setresuid' sysall became available?  */
#if __LINUX_KERNEL_VERSION >= 131584
# define __ASSUME_SETRESUID_SYSCALL	1
#endif
