/* Copyright (C) 1992, 1994, 1997 Free Software Foundation, Inc.
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
#include <sys/socket.h>
#include <hurd.h>
#include <hurd/fd.h>
#include <hurd/socket.h>
#include <string.h>

/* Put the address of the peer connected to socket FD into *ADDR
   (which is *LEN bytes long), and its actual length into *LEN.  */

/* XXX should be __getpeername ? */
int
getpeername (fd, addrarg, len)
     int fd;
     struct sockaddr *addr;
     __SOCKADDR_ARG addrarg;
     size_t *len;
{
  error_t err;
  mach_msg_type_number_t buflen = *len;
  int type;
  struct sockaddr *addr = addrarg.__sockaddr__;
  char *buf = (char *) addr;
  addr_port_t aport;

  if (err = HURD_DPORT_USE (fd, __socket_peername (port, &aport)))
    return __hurd_dfail (fd, err);

  err = __socket_whatis_address (aport, &type, &buf, &buflen);
  __mach_port_deallocate (__mach_task_self (), aport);

  if (err)
    return __hurd_dfail (fd, err);

  if (buf != (char *) addr)
    {
      if (*len < buflen)
	*len = buflen;
      memcpy (addr, buf, *len);
      __vm_deallocate (__mach_task_self (), (vm_address_t) buf, buflen);
    }

  addr->sa_family = type;

  return 0;
}
