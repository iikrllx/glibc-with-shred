/* Copyright (C) 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <unistd.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include <kernel-features.h>

#if defined __NR_pwrite || __ASSUME_PWRITE_SYSCALL > 0

# if __ASSUME_PWRITE_SYSCALL == 0
static ssize_t __emulate_pwrite64 (int fd, const void *buf, size_t count,
				   off64_t offset) internal_function;
# endif


ssize_t
__libc_pwrite64 (fd, buf, count, offset)
     int fd;
     const void *buf;
     size_t count;
     off64_t offset;
{
  ssize_t result;

  /* First try the syscall.  */
  result = INLINE_SYSCALL (pwrite, 5, fd, buf, count,
			   (off_t) (offset & 0xffffffff),
			   (off_t) (offset >> 32));
# if __ASSUME_PWRITE_SYSCALL == 0
  if (result == -1 && errno == ENOSYS)
    /* No system call available.  Use the emulation.  */
    result = __emulate_pwrite64 (fd, buf, count, offset);
# endif

  return result;
}

weak_alias (__libc_pwrite64, __pwrite64)
weak_alias (__libc_pwrite64, pwrite64)

# define __libc_pwrite64(fd, buf, count, offset) \
     static internal_function __emulate_pwrite64 (fd, buf, count, offset)
#endif

#if __ASSUME_PWRITE_SYSCALL == 0
# include <sysdeps/posix/pwrite64.c>
#endif
