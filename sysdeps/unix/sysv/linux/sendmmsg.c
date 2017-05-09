/* Copyright (C) 2011-2017 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gmail.com>, 2011.

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

#include <sysdep-cancel.h>
#include <sys/syscall.h>
#include <socketcall.h>
#include <kernel-features.h>

int
__sendmmsg (int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags)
{
  /* Do not use the sendmmsg syscall on socketcall architectures unless
     it was added at the same time as the socketcall support or can be
     assumed to be present.  */
#if defined __ASSUME_SOCKETCALL \
    && !defined __ASSUME_SENDMMSG_SYSCALL_WITH_SOCKETCALL \
    && !defined __ASSUME_SENDMMSG_SYSCALL
  return SOCKETCALL_CANCEL (sendmmsg, fd, vmessages, vlen, flags);
#else
  return SYSCALL_CANCEL (sendmmsg, fd, vmessages, vlen, flags);
#endif
}
libc_hidden_def (__sendmmsg)
weak_alias (__sendmmsg, sendmmsg)
