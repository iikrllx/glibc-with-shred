/* Copyright (C) 1991, 1995, 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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
#include <stddef.h>
#include <sys/stat.h>

/* Get information about the file descriptor FD in BUF.  */
int
__fxstat (int vers, int fd, struct stat *buf)
{
  if (vers != _STAT_VER)
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (fd < 0)
    {
      __set_errno (EBADF);
      return -1;
    }
  else if (buf == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }

  __set_errno (ENOSYS);
  return -1;
}
stub_warning (__fxstat)

weak_alias (__fxstat, _fxstat)
