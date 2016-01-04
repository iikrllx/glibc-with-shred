/* Copyright (C) 2011-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gmain.com>, 2003.

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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sysdep.h>


int
openat64 (int dfd, const char *file, int oflag, ...)
{
  assert (!__OPEN_NEEDS_MODE (oflag));

#ifdef __NR_openat
  return INLINE_SYSCALL (openat, 3, dfd, file, oflag | O_LARGEFILE);
#else
  return INLINE_SYSCALL_ERROR_RETURN_VALUE (ENOSYS);
#endif
}
