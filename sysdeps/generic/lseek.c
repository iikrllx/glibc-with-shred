/* Copyright (C) 1991, 1995, 1996, 1997, 2002 Free Software Foundation, Inc.
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
#include <unistd.h>
#include <sys/types.h>

/* Seek to OFFSET on FD, starting from WHENCE.  */
off_t
__lseek (fd, offset, whence)
     int fd;
     off_t offset;
     int whence;
{
  if (fd < 0)
    {
      __set_errno (EBADF);
      return -1;
    }
  switch (whence)
    {
    case SEEK_SET:
    case SEEK_CUR:
    case SEEK_END:
      break;
    default:
      __set_errno (EINVAL);
      return -1;
    }

  __set_errno (ENOSYS);
  return -1;
}
stub_warning (lseek)
libc_hidden_def (__lseek)

weak_alias (__lseek, lseek)
#include <stub-tag.h>
