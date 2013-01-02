/* Copyright (C) 1992-2013 Free Software Foundation, Inc.
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

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
int
__setsockopt (int fd,
	      int level,
	      int optname,
	      const void *optval,
	      socklen_t optlen)
{
  error_t err = HURD_DPORT_USE (fd, __socket_setopt (port,
						     level, optname,
						     optval, optlen));
  if (err)
    return __hurd_dfail (fd, err);
  return 0;
}

weak_alias (__setsockopt, setsockopt)
