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
#include <sys/msg.h>
#include <ipc_priv.h>
#include "pthreadP.h"


int
msgsnd (int msqid, const void *msgp, size_t msgsz, int msgflg)
{
  int result;
  int oldtype;

  CANCEL_ASYNC (oldtype);

#ifdef INLINE_SYSCALL
  result = INLINE_SYSCALL (ipc, 5, IPCOP_msgsnd, msqid, msgsz,
			   msgflg, (void *) msgp);
#else
  result = __libc_msgsnd (msqid, msgp, msgsz, msgflg);
#endif

  CANCEL_RESET (oldtype);

  return result;
}
