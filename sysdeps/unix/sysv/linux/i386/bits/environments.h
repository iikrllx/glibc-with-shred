/* Copyright (C) 1999, 2001, 2004 Free Software Foundation, Inc.
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

#ifndef _UNISTD_H
# error "Never include this file directly.  Use <unistd.h> instead"
#endif

/* This header should define the following symbols under the described
   situations.  A value `1' means that the model is always supported,
   `-1' means it is never supported.  Undefined means it cannot be
   statically decided.

   _POSIX_V6_ILP32_OFF32   32bit int, long, pointers, and off_t type
   _POSIX_V6_ILP32_OFFBIG  32bit int, long, and pointers and larger off_t type

   _POSIX_V6_LP64_OFF32	   64bit long and pointers and 32bit off_t type
   _POSIX_V6_LPBIG_OFFBIG  64bit long and pointers and large off_t type

   The macros _XBS5_ILP32_OFF32, _XBS5_ILP32_OFFBIG, _XBS5_LP64_OFF32, and
   _XBS5_LPBIG_OFFBIG were used in previous versions of the Unix standard
   and are available only for compatibility.
*/

/* By default we have 32-bit wide `int', `long int', pointers and `off_t'
   and all platforms support LFS.  */
#define _POSIX_V6_ILP32_OFF32	1
#define _POSIX_V6_ILP32_OFFBIG	1
#define _XBS5_ILP32_OFF32	1
#define _XBS5_ILP32_OFFBIG	1

/* We optionally provide an environment with the above size but an 64-bit
   side `off_t'.  Therefore we don't define _XBS5_ILP32_OFFBIG.  */

/* Environments with 64-bit wide pointers can be provided,
   so these macros aren't defined:
   # undef _POSIX_V6_LP64_OFF64
   # undef _POSIX_V6_LPBIG_OFFBIG
   # undef _XBS5_LP64_OFF64
   # undef _XBS5_LPBIG_OFFBIG
   and sysconf tests for it at runtime.  */

#define __ILP32_OFF32_CFLAGS	"-m32"
#define __ILP32_OFFBIG_CFLAGS	"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"
#define __ILP32_OFF32_LDFLAGS	"-m32"
#define __ILP32_OFFBIG_LDFLAGS	"-m32"
#define __LP64_OFF64_CFLAGS	"-m64"
#define __LP64_OFF64_LDFLAGS	"-m64"
