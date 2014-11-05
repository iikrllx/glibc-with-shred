/* Message-writing for the dynamic linker.  Generic version.
   Copyright (C) 2013-2014 Free Software Foundation, Inc.
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

#include <sys/uio.h>
#include <ldsodefs.h>
#include <bits/libc-lock.h>

/* This is used from only one place: dl-misc.c:_dl_debug_vdprintf.
   Hence it's in a header with the expectation it will be inlined.

   This is writev, but with a constraint added and others loosened:

   1. Under RTLD_PRIVATE_ERRNO, it must not clobber the private errno
      when another thread holds the dl_load_lock.
   2. It is not obliged to detect and report errors at all.
   3. It's not really obliged to deliver a single atomic write
      (though it may be preferable).  */

static inline void
_dl_writev (int fd, const struct iovec *iov, size_t niov)
{
  /* Note that if __writev is an implementation that calls malloc,
     this will cause linking problems building the dynamic linker.  */

#if RTLD_PRIVATE_ERRNO
  /* We have to take this lock just to be sure we don't clobber the private
     errno when it's being used by another thread that cares about it.
     Yet we must be sure not to try calling the lock functions before
     the thread library is fully initialized.  */
  if (__glibc_unlikely (_dl_starting_up))
    __writev (fd, iov, niov);
  else
    {
      __rtld_lock_lock_recursive (GL(dl_load_lock));
      __writev (fd, iov, niov);
      __rtld_lock_unlock_recursive (GL(dl_load_lock));
    }
#else
  __writev (fd, iov, niov);
#endif
}
