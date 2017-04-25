/* Linux implementation of pwritev2 (LFS version).
   Copyright (C) 2017 Free Software Foundation, Inc.
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
#include <sysdep-cancel.h>

#if !defined(__NR_pwritev64v2) && defined(__NR_pwritev2)
# define __NR_pwritev64v2 __NR_pwritev2
#endif

ssize_t
pwritev64v2 (int fd, const struct iovec *vector, int count, off64_t offset,
	     int flags)
{
#ifdef __NR_pwritev64v2
  ssize_t result = SYSCALL_CANCEL (pwritev64v2, fd, vector, count,
				   LO_HI_LONG (offset), flags);
  if (result >= 0 || errno != ENOSYS)
    return result;
#endif
  /* Trying to emulate the pwritev2 syscall flags is troublesome:

     * We can not temporary change the file state of the O_DSYNC and O_SYNC
       flags to emulate RWF_{D}SYNC (attempts to change the state of using
       fcntl are silently ignored).

     * IOCB_HIPRI requires the file opened in O_DIRECT and uses an internal
       semantic not provided by any other flag (O_NONBLOCK for instance).  */

  if (flags != 0)
    {
      __set_errno (EOPNOTSUPP);
      return -1;
    }
  return pwritev64 (fd, vector, count, offset);
}

#ifdef __OFF_T_MATCHES_OFF64_T
strong_alias (pwritev64v2, pwritev2)
#endif
