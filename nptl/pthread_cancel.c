/* Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
#include <signal.h>
#include "pthreadP.h"
#include "atomic.h"
#include <sysdep.h>
#include <kernel-features.h>


int
pthread_cancel (th)
     pthread_t th;
{
  volatile struct pthread *pd = (volatile struct pthread *) th;

  /* Make sure the descriptor is valid.  */
  if (INVALID_TD_P (pd))
    /* Not a valid thread handle.  */
    return ESRCH;

#ifdef SHARED
  pthread_cancel_init ();
#endif
  int result = 0;
  int oldval;
  int newval;
  do
    {
      oldval = pd->cancelhandling;
      newval = oldval | CANCELING_BITMASK | CANCELED_BITMASK;

      /* Avoid doing unnecessary work.  The atomic operation can
	 potentially be expensive if the bug has to be locked and
	 remote cache lines have to be invalidated.  */
      if (oldval == newval)
	break;

      /* If the cancellation is handled asynchronously just send a
	 signal.  We avoid this if possible since it's more
	 expensive.  */
      if (CANCEL_ENABLED_AND_CANCELED_AND_ASYNCHRONOUS (newval))
	{
	  /* Mark the cancellation as "in progress".  */
	  atomic_bit_set (&pd->cancelhandling, CANCELING_BIT);

	  /* The cancellation handler will take care of marking the
	     thread as canceled.  */
	  INTERNAL_SYSCALL_DECL (err);

	  int val;
#if __ASSUME_TGKILL
	  val = INTERNAL_SYSCALL (tgkill, err, 3,
				  THREAD_GETMEM (THREAD_SELF, pid), pd->tid,
				  SIGCANCEL);
#else
# ifdef __NR_tgkill
	  val = INTERNAL_SYSCALL (tgkill, err, 3,
				  THREAD_GETMEM (THREAD_SELF, pid), pd->tid,
				  SIGCANCEL);
	  if (INTERNAL_SYSCALL_ERROR_P (val, err)
	      && INTERNAL_SYSCALL_ERRNO (val, err) == ENOSYS)
# endif
	    val = INTERNAL_SYSCALL (tkill, err, 2, pd->tid, SIGCANCEL);
#endif

	  if (INTERNAL_SYSCALL_ERROR_P (val, err))
	    result = INTERNAL_SYSCALL_ERRNO (val, err);

	  break;
	}
    }
  /* Mark the thread as canceled.  This has to be done
     atomically since other bits could be modified as well.  */
  while (atomic_compare_and_exchange_bool_acq (&pd->cancelhandling, newval,
					       oldval));

  return result;
}
