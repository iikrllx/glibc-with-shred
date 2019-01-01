/* Copyright (C) 2018-2019 Free Software Foundation, Inc.
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

#define USE_VERSIONED_RLIMIT
#include <sysdeps/unix/sysv/linux/getrlimit64.c>
versioned_symbol (libc, __getrlimit, getrlimit, GLIBC_2_27);
versioned_symbol (libc, __getrlimit64, getrlimit64, GLIBC_2_27);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_27)
/* RLIM64_INFINITY was supposed to be a glibc convention rather than
   anything seen by the kernel, but it ended being passed to the kernel
   through the prlimit64 syscall.  Given that a lot of binaries with
   the wrong constant value are in the wild, provide a wrapper function
   fixing the value after the syscall.  */
# define OLD_RLIM64_INFINITY           0x7fffffffffffffffULL

int
attribute_compat_text_section
__old_getrlimit64 (enum __rlimit_resource resource,
		   struct rlimit64 *rlimits)
{
  struct rlimit64 krlimits;

  if (__getrlimit64 (resource, &krlimits) < 0)
    return -1;

  if (krlimits.rlim_cur == RLIM64_INFINITY)
    rlimits->rlim_cur = OLD_RLIM64_INFINITY;
  else
    rlimits->rlim_cur = krlimits.rlim_cur;
  if (krlimits.rlim_max == RLIM64_INFINITY)
    rlimits->rlim_max = OLD_RLIM64_INFINITY;
  else
    rlimits->rlim_max = krlimits.rlim_max;

  return 0;
}

strong_alias (__old_getrlimit64, __old_getrlimit)
compat_symbol (libc, __old_getrlimit, getrlimit, GLIBC_2_0);
compat_symbol (libc, __old_getrlimit64, getrlimit64, GLIBC_2_1);
#endif
