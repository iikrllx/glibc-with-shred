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

#include <assert.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>

#include <sysdep.h>
#include <sys/syscall.h>
#include <bp-checks.h>
#include <nptl/pthreadP.h>
#include <tls.h>

#ifndef __NR_pwrite64
# error "__NR_pwrite64 must be defined"
#endif


/* The order of hi, lo depends on endianness.  */
extern ssize_t __syscall_pwrite64 (int fd, const void *__unbounded buf,
				   size_t count, off_t offset_hi,
				   off_t offset_lo);


ssize_t
__libc_pwrite (fd, buf, count, offset)
     int fd;
     const void *buf;
     size_t count;
     off_t offset;
{
  /* First try the syscall.  */
  assert (sizeof (offset) == 4);
#ifndef NOT_IN_libc
  if (__builtin_expect (THREAD_GETMEM (THREAD_SELF,
				       header.data.multiple_threads) == 0, 1))
    return INLINE_SYSCALL (pwrite64, 5, fd, CHECK_N (buf, count), count,
			   __LONG_LONG_PAIR (offset >> 31, offset));

  int oldtype = LIBC_CANCEL_ASYNC ();
#endif

  ssize_t result = INLINE_SYSCALL (pwrite64, 5, fd, CHECK_N (buf, count),
				   count,
				   __LONG_LONG_PAIR (offset >> 31, offset));

#ifndef NOT_IN_libc
  LIBC_CANCEL_RESET (oldtype);
#endif

  return result;
}

strong_alias (__libc_pwrite, __pwrite)
weak_alias (__libc_pwrite, pwrite)
