/* Copyright (C) 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Martin Schwidefsky <schwidefsky@de.ibm.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <endian.h>
#include <errno.h>
#include <sysdep.h>
#include <lowlevellock.h>
#include <pthread.h>
#include <pthreadP.h>

#include <shlib-compat.h>


struct _condvar_cleanup_buffer
{
  int oldtype;
  pthread_cond_t *cond;
  pthread_mutex_t *mutex;
};

void
__attribute__ ((visibility ("hidden")))
__condvar_cleanup (void *arg)
{
  struct _condvar_cleanup_buffer *cbuffer =
    (struct _condvar_cleanup_buffer *) arg;

  /* We are going to modify shared data.  */
  lll_mutex_lock (cbuffer->cond->__data.__lock);

  /* This thread is not waiting anymore.  Adjust the sequence counters
     appropriately.  */
  ++cbuffer->cond->__data.__wakeup_seq;
  ++cbuffer->cond->__data.__woken_seq;

  /* We are done.  */
  lll_mutex_unlock (cbuffer->cond->__data.__lock);

  /* Get the mutex before returning unless asynchronous cancellation
     is in effect.  */
  if (!(cbuffer->oldtype & CANCELTYPE_BITMASK))
    __pthread_mutex_lock_internal (cbuffer->mutex);
}


int
__pthread_cond_wait (cond, mutex)
     pthread_cond_t *cond;
     pthread_mutex_t *mutex;
{
  struct _pthread_cleanup_buffer buffer;
  struct _condvar_cleanup_buffer cbuffer;
  int err;

  /* Make sure we are along.  */
  lll_mutex_lock (cond->__data.__lock);

  /* Now we can release the mutex.  */
  err = __pthread_mutex_unlock_internal (mutex);
  if (err)
    {
      lll_mutex_unlock (cond->__data.__lock);
      return err;
    }

  /* We have one new user of the condvar.  */
  ++cond->__data.__total_seq;

  /* Prepare structure passed to cancellation handler.  */
  cbuffer.cond = cond;
  cbuffer.mutex = mutex;

  /* Before we block we enable cancellation.  Therefore we have to
     install a cancellation handler.  */
  __pthread_cleanup_push (&buffer, __condvar_cleanup, &cbuffer);

  /* The current values of the wakeup counter.  The "woken" counter
     must exceed this value.  */
  unsigned long long int val;
  unsigned long long int seq;
  val = seq = cond->__data.__wakeup_seq;

  /* The futex syscall operates on a 32-bit word.  That is fine, we
     just use the low 32 bits of the sequence counter.  */
#if BYTE_ORDER == LITTLE_ENDIAN
  int *futex = ((int *) (&cond->__data.__wakeup_seq));
#elif BYTE_ORDER == BIG_ENDIAN
  int *futex = ((int *) (&cond->__data.__wakeup_seq)) + 1;
#else
# error "No valid byte order"
#endif

  while (1)
    {
      /* Prepare to wait.  Release the condvar futex.  */
      lll_mutex_unlock (cond->__data.__lock);

      /* Enable asynchronous cancellation.  Required by the standard.  */
      cbuffer.oldtype = __pthread_enable_asynccancel ();

      /* Wait until woken by signal or broadcast.  Note that we
	 truncate the 'val' value to 32 bits.  */
      lll_futex_wait (futex, (unsigned int) val);

      /* Disable asynchronous cancellation.  */
      __pthread_disable_asynccancel (cbuffer.oldtype);

      /* We are going to look at shared data again, so get the lock.  */
      lll_mutex_lock(cond->__data.__lock);

      /* Check whether we are eligible for wakeup.  */
      val = cond->__data.__wakeup_seq;
      if (cond->__data.__woken_seq >= seq
	  && cond->__data.__woken_seq < val)
	break;
    }

  /* Another thread woken up.  */
  ++cond->__data.__woken_seq;

  /* We are done with the condvar.  */
  lll_mutex_unlock (cond->__data.__lock);

  /* The cancellation handling is back to normal, remove the handler.  */
  __pthread_cleanup_pop (&buffer, 0);

  /* Get the mutex before returning.  */
  __pthread_mutex_lock_internal (mutex);

  return 0;
}

versioned_symbol (libpthread, __pthread_cond_wait, pthread_cond_wait,
		  GLIBC_2_3_2);
