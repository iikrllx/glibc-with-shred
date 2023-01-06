/* 64-bit time_t stat with error checking.
   Copyright (C) 2021-2023 Free Software Foundation, Inc.
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

/* NB: Non-standard file name to avoid sysdeps override for xstat.  */

#include <support/check.h>
#include <support/xunistd.h>
#include <sys/stat.h>

#if __TIMESIZE != 64
void
xfstat_time64 (int fd, struct __stat64_t64 *result)
{
  if (__fstat64_time64 (fd, result) != 0)
    FAIL_EXIT1 ("__fstat64_time64 (%d): %m", fd);
}
#endif
