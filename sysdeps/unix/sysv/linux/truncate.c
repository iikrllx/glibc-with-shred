/* Copyright (C) 2016-2019 Free Software Foundation, Inc.
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

#include <unistd.h>
#include <sysdep.h>
#include <errno.h>

#ifndef __OFF_T_MATCHES_OFF64_T
/* Truncate PATH to LENGTH bytes.  */
int
__truncate (const char *path, off_t length)
{
# ifndef __NR_truncate
  return INLINE_SYSCALL_CALL (truncate64, path,
			      __ALIGNMENT_ARG SYSCALL_LL (length));
# else
  return INLINE_SYSCALL_CALL (truncate, path, length);
# endif
}
weak_alias (__truncate, truncate)
#endif
