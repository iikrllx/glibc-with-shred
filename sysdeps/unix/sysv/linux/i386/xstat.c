/* xstat using old-style Unix stat system call.
   Copyright (C) 1991-2012 Free Software Foundation, Inc.
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

/* Ho hum, if xstat == xstat64 we must get rid of the prototype or gcc
   will complain since they don't strictly match.  */
#define __xstat64 __xstat64_disable

#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <kernel_stat.h>

#include <sysdep.h>
#include <sys/syscall.h>
#include <bp-checks.h>

#include <kernel-features.h>

#include <xstatconv.h>


/* Get information about the file NAME in BUF.  */
int
__xstat (int vers, const char *name, struct stat *buf)
{
  int result;

  if (vers == _STAT_VER_KERNEL)
    return INLINE_SYSCALL (stat, 2, CHECK_STRING (name), CHECK_1 ((struct kernel_stat *) buf));

  {
    struct stat64 buf64;

    result = INLINE_SYSCALL (stat64, 2, CHECK_STRING (name), __ptrvalue (&buf64));
    if (result == 0)
      result = __xstat32_conv (vers, &buf64, buf);
    return result;
  }
}
hidden_def (__xstat)
weak_alias (__xstat, _xstat);
#ifdef XSTAT_IS_XSTAT64
# undef __xstat64
strong_alias (__xstat, __xstat64);
hidden_ver (__xstat, __xstat64)
#endif
