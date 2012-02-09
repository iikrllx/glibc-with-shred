/* Set flags signalling availability of certain operating system features.
   Copyright (C) 2007 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* This file can define __ASSUME_* macros checked by certain source files.
   Almost none of these are used outside of sysdeps/unix/sysv/linux code.
   But those referring to POSIX-level features like O_* flags can be.  */

#include <fcntl.h>

/* If a system defines the O_CLOEXEC constant but it is sometimes ignored,
   it must override this file to define __ASSUME_O_CLOEXEC conditionally
   (or not at all) to indicate when O_CLOEXEC actually works.  */
#ifdef O_CLOEXEC
# define __ASSUME_O_CLOEXEC	1
#endif
