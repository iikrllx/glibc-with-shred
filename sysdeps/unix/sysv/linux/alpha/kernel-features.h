/* Set flags signalling availability of kernel features based on given
   kernel version number.
   Copyright (C) 2010-2014 Free Software Foundation, Inc.
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
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _KERNEL_FEATURES_H
#define _KERNEL_FEATURES_H 1

#define __ASSUME_UTIMES	1

/* Support for the O_CLOEXEC flag was added for alpha in 2.6.23.  */
#define __ASSUME_O_CLOEXEC    1

/* Support for various CLOEXEC and NONBLOCK flags was added for alpha after
   2.6.33-rc1.  */
#if __LINUX_KERNEL_VERSION >= 0x020621
# define __ASSUME_SOCK_CLOEXEC  1
# define __ASSUME_IN_NONBLOCK   1
#endif

/* Support for the pipe2, eventfd2, signalfd4 syscalls was added for alpha
   after 2.6.33-rc1.  */
#if __LINUX_KERNEL_VERSION >= 0x020621
# define __ASSUME_PIPE2     1
# define __ASSUME_EVENTFD2  1
# define __ASSUME_SIGNALFD4 1
#endif

/* Support for recvmmsg was added for alpha in 2.6.33.  */
#if __LINUX_KERNEL_VERSION >= 0x020621
# define __ASSUME_RECVMMSG_SYSCALL       1
#endif

/* Support for accept4 and sendmmsg was added for alpha in 3.2.  */
#if __LINUX_KERNEL_VERSION >= 0x030200
# define __ASSUME_ACCEPT4_SYSCALL      1
# define __ASSUME_SENDMMSG_SYSCALL     1
#endif

#include_next <kernel-features.h>

#undef __ASSUME_ST_INO_64_BIT

/* Support for fallocate was added for alpha after 2.6.33-rc1.  */
#if __LINUX_KERNEL_VERSION < 0x020621
# undef __ASSUME_FALLOCATE
#endif

/* There never has been support for fstat64.  */
#undef __ASSUME_STATFS64
#define __ASSUME_STATFS64 0

/* Support for fsyncdata was added for alpha after 2.6.21.  */
#define __ASSUME_FDATASYNC	1

/* Support for preadv and pwritev was added for alpha in 2.6.33.  */
#if __LINUX_KERNEL_VERSION < 0x020621
# undef __ASSUME_PREADV
# undef __ASSUME_PWRITEV
#endif

#endif /* _KERNEL_FEATURES_H */
