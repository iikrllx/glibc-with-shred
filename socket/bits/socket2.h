/* Checking macros for socket functions.
   Copyright (C) 2005, 2007 Free Software Foundation, Inc.
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

#ifndef _SYS_SOCKET_H
# error "Never include <bits/socket2.h> directly; use <sys/socket.h> instead."
#endif

extern ssize_t __recv_chk (int __fd, void *__buf, size_t __n, size_t __buflen,
			   int __flags);
extern ssize_t __REDIRECT (__recv_alias, (int __fd, void *__buf, size_t __n,
					  int __flags), recv);

__extern_always_inline ssize_t
recv (int __fd, void *__buf, size_t __n, int __flags)
{
  if (__bos0 (__buf) != (size_t) -1
      && (!__builtin_constant_p (__n) || __n > __bos0 (__buf)))
    return __recv_chk (__fd, __buf, __n, __bos0 (__buf), __flags);
  return __recv_alias (__fd, __buf, __n, __flags);
}

extern ssize_t __recvfrom_chk (int __fd, void *__restrict __buf, size_t __n,
			       size_t __buflen, int __flags,
			       __SOCKADDR_ARG __addr,
			       socklen_t *__restrict __addr_len);
extern ssize_t __REDIRECT (__recvfrom_alias,
			   (int __fd, void *__restrict __buf, size_t __n,
			    int __flags, __SOCKADDR_ARG __addr,
			    socklen_t *__restrict __addr_len), recvfrom);

__extern_always_inline ssize_t
recvfrom (int __fd, void *__restrict __buf, size_t __n, int __flags,
	  __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len)
{
  if (__bos0 (__buf) != (size_t) -1
      && (!__builtin_constant_p (__n) || __n > __bos0 (__buf)))
    return __recvfrom_chk (__fd, __buf, __n, __bos0 (__buf), __flags,
			   __addr, __addr_len);
  return __recvfrom_alias (__fd, __buf, __n, __flags, __addr, __addr_len);
}
