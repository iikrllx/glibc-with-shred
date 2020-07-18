/* lxstat64 using 64-bit MIPS lstat system call.
   Copyright (C) 1997-2020 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <sys/stat.h>
#include <kernel_stat.h>
#include <sysdep.h>
#include <xstatconv.h>
#include <shlib-compat.h>

#if SHLIB_COMPAT(libc, GLIBC_2_2, GLIBC_2_33)

/* Get information about the file NAME in BUF.  */
int
attribute_compat_text_section
__lxstat64 (int vers, const char *name, struct stat64 *buf)
{
  struct kernel_stat kbuf;
  int r = INLINE_SYSCALL_CALL (lstat, name, &kbuf);
  return r ?: __xstat64_conv (vers, &kbuf, buf);
}

compat_symbol (libc, __lxstat64, __lxstat64, GLIBC_2_2);

#endif
