/* Copyright (C) 1997, 1998, 2000, 2002, 2003, 2004, 2006
   Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>

#include <sysdep-cancel.h>
#include <sys/syscall.h>
#include <bp-checks.h>

#include <kernel-features.h>

#ifdef __NR_pwrite64            /* Newer kernels renamed but it's the same.  */
# ifdef __NR_pwrite
#  error "__NR_pwrite and __NR_pwrite64 both defined???"
# endif
# define __NR_pwrite __NR_pwrite64
#endif

#if defined __NR_pwrite || __ASSUME_PWRITE_SYSCALL > 0

# if __ASSUME_PWRITE_SYSCALL == 0
static ssize_t __emulate_pwrite (int fd, const void *buf, size_t count,
				 off_t offset) internal_function;
# endif

ssize_t
__libc_pwrite (fd, buf, count, offset)
     int fd;
     const void *buf;
     size_t count;
     off_t offset;
{
  ssize_t result;

  if (SINGLE_THREAD_P)
    {
      /* First try the syscall.  */
      result = INLINE_SYSCALL (pwrite, 6, fd, CHECK_N (buf, count), count, 0,
			       __LONG_LONG_PAIR (offset >> 31, offset));
# if __ASSUME_PWRITE_SYSCALL == 0
      if (result == -1 && errno == ENOSYS)
        /* No system call available.  Use the emulation.  */
        result = __emulate_pwrite (fd, buf, count, offset);
# endif
      return result;
    }

  int oldtype = LIBC_CANCEL_ASYNC ();

  /* First try the syscall.  */
  result = INLINE_SYSCALL (pwrite, 6, fd, CHECK_N (buf, count), count, 0,
			   __LONG_LONG_PAIR (offset >> 31, offset));
# if __ASSUME_PWRITE_SYSCALL == 0
  if (result == -1 && errno == ENOSYS)
    /* No system call available.  Use the emulation.  */
    result = __emulate_pwrite (fd, buf, count, offset);
# endif

  LIBC_CANCEL_RESET (oldtype);

  return result;
}

strong_alias (__libc_pwrite, __pwrite)
weak_alias (__libc_pwrite, pwrite)

# define __libc_pwrite(fd, buf, count, offset) \
     static internal_function __emulate_pwrite (fd, buf, count, offset)
#endif

#if __ASSUME_PWRITE_SYSCALL == 0
# include <sysdeps/posix/pwrite.c>
#endif
