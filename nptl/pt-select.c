/* Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

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
#include <stdlib.h>
#include <sysdep.h>
#include <unistd.h>
#include "pthreadP.h"


int
select (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	struct timeval *timeout)
{
  int result;
  int oldtype;

  CANCEL_ASYNC (oldtype);

#if defined INLINE_SYSCALL && defined __NR__newselect
  result = INLINE_SYSCALL (_newselect, 5, nfds, readfds, writefds, exceptfds,
			   timeout);
#else
  result = __select (nfds, readfds, writefds, exceptfds, timeout);
#endif

  CANCEL_RESET (oldtype);

  return result;
}
