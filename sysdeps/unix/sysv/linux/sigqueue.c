/* Copyright (C) 1997, 1998 Free Software Foundation, Inc.
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

#include <signal.h>
#include <unistd.h>

extern int __syscall_rt_sigqueueinfo (int, int, siginfo_t *);

/* These variables are used quite often in the libc code.  */
extern pid_t __libc_pid;


/* Return any pending signal or wait for one for the given time.  */
int
__sigqueue (pid, sig, val)
     pid_t pid;
     int sig;
     const union sigval val;
{
  siginfo_t info;

  /* We must pass the information about the data in a siginfo_t value.  */
  info.si_signo = sig;
  info.si_errno = 0;
  info.si_code = SI_QUEUE;

  if (__libc_pid == 0xf00baa)
    __libc_pid = __getpid ();
  info.si_pid = __libc_pid;

  info.si_uid = __getuid ();
  info.si_value = val;

  return __syscall_rt_sigqueueinfo (pid, sig, &info);
}
weak_alias (__sigqueue, sigqueue)
