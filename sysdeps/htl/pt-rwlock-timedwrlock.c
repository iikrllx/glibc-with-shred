/* Acquire a rwlock for writing.  Generic version.
   Copyright (C) 2002-2018 Free Software Foundation, Inc.
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
   License along with the GNU C Library;  if not, see
   <http://www.gnu.org/licenses/>.  */

#include <pthread.h>
#include <assert.h>

#include <pt-internal.h>

/* Acquire RWLOCK for writing blocking until *ABSTIME if we cannot get
   it.  As a special GNU extension, if ABSTIME is NULL then the wait
   shall not time out.  */
int
__pthread_rwlock_timedwrlock_internal (struct __pthread_rwlock *rwlock,
				       const struct timespec *abstime)
{
  error_t err;
  int drain;
  struct __pthread *self;

  __pthread_spin_lock (&rwlock->__lock);
  if (__pthread_spin_trylock (&rwlock->__held) == 0)
    /* Successfully acquired the lock.  */
    {
      assert (rwlock->__readerqueue == 0);
      assert (rwlock->__writerqueue == 0);
      assert (rwlock->__readers == 0);

      __pthread_spin_unlock (&rwlock->__lock);
      return 0;
    }

  /* The lock is busy.  */

  if (abstime != NULL && (abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000))
    return EINVAL;

  self = _pthread_self ();

  /* Add ourselves to the queue.  */
  __pthread_enqueue (&rwlock->__writerqueue, self);
  __pthread_spin_unlock (&rwlock->__lock);

  /* Block the thread.  */
  if (abstime != NULL)
    err = __pthread_timedblock (self, abstime, CLOCK_REALTIME);
  else
    {
      err = 0;
      __pthread_block (self);
    }

  __pthread_spin_lock (&rwlock->__lock);
  if (self->prevp == NULL)
    /* Another thread removed us from the queue, which means a wakeup message
       has been sent.  It was either consumed while we were blocking, or
       queued after we timed out and before we acquired the rwlock lock, in
       which case the message queue must be drained.  */
    drain = err ? 1 : 0;
  else
    {
      /* We're still in the queue.  Noone attempted to wake us up, i.e. we
         timed out.  */
      __pthread_dequeue (self);
      drain = 0;
    }
  __pthread_spin_unlock (&rwlock->__lock);

  if (drain)
    __pthread_block (self);

  if (err)
    {
      assert (err == ETIMEDOUT);
      return err;
    }

  assert (rwlock->__readers == 0);

  return 0;
}

int
__pthread_rwlock_timedwrlock (struct __pthread_rwlock *rwlock,
			      const struct timespec *abstime)
{
  return __pthread_rwlock_timedwrlock_internal (rwlock, abstime);
}
weak_alias (__pthread_rwlock_timedwrlock, pthread_rwlock_timedwrlock)
