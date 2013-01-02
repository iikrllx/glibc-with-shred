/* Copyright (C) 1994-2013 Free Software Foundation, Inc.
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
#include <sys/socket.h>
#include <hurd.h>
#include <hurd/socket.h>
#include <hurd/fd.h>

/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.  */
ssize_t
__send (fd, buf, n, flags)
     int fd;
     const void *buf;
     size_t n;
     int flags;
{
  error_t err;
  size_t wrote;

  err = HURD_DPORT_USE (fd, __socket_send (port, MACH_PORT_NULL,
					   flags, buf, n,
					   NULL, MACH_MSG_TYPE_COPY_SEND, 0,
					   NULL, 0, &wrote));

  return err ? __hurd_sockfail (fd, flags, err) : wrote;
}
libc_hidden_def (__send)
weak_alias (__send, send)
