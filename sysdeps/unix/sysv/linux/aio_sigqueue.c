/* Copyright (C) 1997, 1998, 1999 Free Software Foundation, Inc.
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

#include <aio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include "aio_misc.h"

#ifdef __NR_rt_sigqueueinfo
extern int __syscall_rt_sigqueueinfo (int, int, siginfo_t *);


/* Return any pending signal or wait for one for the given time.  */
int
__aio_sigqueue (sig, val, caller_pid)
     int sig;
     const union sigval val;
     pid_t caller_pid;
{
  siginfo_t info;

  /* We must pass the information about the data in a siginfo_t value.  */
  info.si_signo = sig;
  info.si_errno = 0;
  info.si_code = SI_ASYNCIO;
  info.si_pid = caller_pid;
  info.si_uid = getuid ();
  info.si_value = val;

  return INLINE_SYSCALL (rt_sigqueueinfo, 3, info.si_pid, sig, &info);
}
#else
# include <sysdeps/generic/aio_sigqueue.c>
#endif
