/* Copyright (C) 1997, 1998, 1999, 2000, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <errno.h>
#include <unistd.h>

#include <sysdep.h>
#include <sys/syscall.h>
#include <bp-checks.h>

#ifdef __NR_pwrite

extern ssize_t __syscall_pwrite (int fd, const void *buf, size_t count,
				   off64_t offset);

static ssize_t __emulate_pwrite64 (int fd, const void *buf, size_t count,
				   off64_t offset) internal_function;


ssize_t
__libc_pwrite64 (fd, buf, count, offset)
     int fd;
     const void *buf;
     size_t count;
     off64_t offset;
{
  ssize_t result;

  /* First try the syscall.  */
  result = __syscall_pwrite (fd, CHECK_N (buf, count), count, offset);
  if (result == -1 && errno == ENOSYS)
    /* No system call available.  Use the emulation.  */
    result = __emulate_pwrite64 (fd, buf, count, offset);

  return result;
}

weak_alias (__libc_pwrite64, __pwrite64)
libc_hidden_def (__pwrite64)
weak_alias (__libc_pwrite64, pwrite64)

#define __libc_pwrite64(fd, buf, count, offset) \
     static internal_function __emulate_pwrite64 (fd, buf, count, offset)
#endif
#include <sysdeps/posix/pwrite64.c>
