/* Copyright (C) 1997, 1998, 2000, 2002 Free Software Foundation, Inc.
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

#include <errno.h>
#include <signal.h>
#define __need_NULL
#include <stddef.h>

#include <sysdep.h>
#include <sys/syscall.h>
#include <bp-checks.h>
#include <nptl/pthreadP.h>
#include <tls.h>

extern int __syscall_rt_sigtimedwait (const sigset_t *__unbounded, siginfo_t *__unbounded,
				      const struct timespec *__unbounded, size_t);


/* Return any pending signal or wait for one for the given time.  */
static int
do_sigwait (const sigset_t *set, int *sig)
{
  int ret;

  /* XXX The size argument hopefully will have to be changed to the
     real size of the user-level sigset_t.  */
#ifdef INTERNAL_SYSCALL
  ret = INTERNAL_SYSCALL (rt_sigtimedwait, 4, CHECK_SIGSET (set),
			  NULL, NULL, _NSIG / 8);
  if (! INTERNAL_SYSCALL_ERROR_P (ret))
    {
      *sig = ret;
      ret = 0;
    }
  else
    ret = INTERNAL_SYSCALL_ERRNO (ret);
#else
  ret = INLINE_SYSCALL (rt_sigtimedwait, 4, CHECK_SIGSET (set),
			NULL, NULL, _NSIG / 8);
  if (ret != -1)
    {
      *sig = ret;
      ret = 0;
    }
  else
    ret = errno;
#endif

  return ret;
}


int
__sigwait (set, sig)
     const sigset_t *set;
     int *sig;
{
#ifndef NOT_IN_libc
  if (__builtin_expect (THREAD_GETMEM (THREAD_SELF,
				       header.data.multiple_threads) == 0, 1))
    return do_sigwait (set, sig);

  int oldtype = LIBC_CANCEL_ASYNC ();
#endif

  int result = do_sigwait (set, sig);

#ifndef NOT_IN_libc
  LIBC_CANCEL_RESET (oldtype);
#endif

  return result;
}
libc_hidden_def (__sigwait)
weak_alias (__sigwait, sigwait)
strong_alias (__sigwait, __libc_sigwait)
