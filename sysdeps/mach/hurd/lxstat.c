/* Copyright (C) 1992-2023 Free Software Foundation, Inc.
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

#include <errno.h>
#include <sys/stat.h>
#include <stddef.h>
#include <hurd.h>
#include <shlib-compat.h>

#if LIB_COMPAT(libc, GLIBC_2_0, GLIBC_2_33)

int
__lxstat (int vers, const char *file, struct stat *buf)
{
  if (vers != _STAT_VER)
    return __hurd_fail (EINVAL);

  return __lstat (file, buf);
}
weak_alias (__lxstat, _lxstat)

#endif
