/* futimes -- change access and modification times of open file.  Stub version.
   Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <errno.h>
#include <sysdep.h>
#include <utime.h>
#include <sys/time.h>
#include <stdio-common/_itoa.h>

#include "kernel-features.h"

/* Change the access time of FILE to TVP[0] and
   the modification time of FILE to TVP[1], but do not follow symlinks.

   The Linux kernel has no futimes() syscall so we use the /proc
   filesystem.  */
int
__futimes (int fd, const struct timeval tvp[2])
{
  static const char selffd[] = "/proc/self/fd/";
  char fname[sizeof (selffd) + 3 * sizeof (int)];
  fname[sizeof (fname) - 1] = '\0';
  char *cp = _itoa_word ((unsigned int) fd, fname + sizeof (fname) - 1, 10, 0);
  cp = memcpy (cp - sizeof (selffd) + 1, selffd, sizeof (selffd) - 1);

#ifdef __NR_utimes
  int result = INLINE_SYSCALL (utimes, 2, cp, tvp);
# ifndef __ASSUME_UTIMES
  if (result != -1 || errno != ENOSYS)
# endif
    return result;
#endif

  /* The utimes() syscall does not exist or is not available in the
     used kernel.  Use utime().  For this we have to convert to the
     data format utime() expects.  */
#ifndef __ASSUME_UTIMES
  struct utimbuf buf;
  struct utimbuf *times;

  if (tvp != NULL)
    {
      times = &buf;
      buf.actime = tvp[0].tv_sec + tvp[0].tv_usec >= 500000;
      buf.modtime = tvp[1].tv_sec + tvp[1].tv_usec >= 500000;
    }
  else
    times = NULL;

  return INLINE_SYSCALL (utime, 2, cp, times);
#endif
}
weak_alias (__futimes, futimes)
