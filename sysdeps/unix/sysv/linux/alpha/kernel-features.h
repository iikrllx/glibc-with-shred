/* Set flags signalling availability of kernel features based on given
   kernel version number.
   Copyright (C) 2010-2016 Free Software Foundation, Inc.
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

/* Support for recvmmsg was added for alpha in 2.6.33.  */
#define __ASSUME_RECVMMSG_SYSCALL       1

/* Support for accept4 and sendmmsg was added for alpha in 3.2.  */
#define __ASSUME_ACCEPT4_SYSCALL      1
#define __ASSUME_SENDMMSG_SYSCALL     1

#include_next <kernel-features.h>

#undef __ASSUME_ST_INO_64_BIT

/* There never has been support for fstat64.  */
#undef __ASSUME_STATFS64
#define __ASSUME_STATFS64 0

#endif /* _KERNEL_FEATURES_H */
