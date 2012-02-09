/* Copyright (C) 2007, 2009, 2011 Free Software Foundation, Inc.
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

#include <errno.h>
#include <fcntl.h>
#include <sysdep-cancel.h>


extern int __call_fallocate (int fd, int mode, __off64_t offset, __off64_t len)
     attribute_hidden;


/* Reserve storage for the data of the file associated with FD.  */
int
fallocate (int fd, int mode, __off_t offset, __off_t len)
{
#ifdef __NR_fallocate
  int err;
  if (SINGLE_THREAD_P)
    err = __call_fallocate (fd, mode, offset, len);
  else
    {
      int oldtype = LIBC_CANCEL_ASYNC ();

      err = __call_fallocate (fd, mode, offset, len);

      LIBC_CANCEL_RESET (oldtype);
    }
  if (__builtin_expect (err, 0))
    {
      __set_errno (err);
      err = -1;
    }
  return err;
#else
  __set_errno (ENOSYS);
  return -1;
#endif
}
