/* Linuxthreads - a simple clone()-based implementation of Posix        */
/* threads for Linux.                                                   */
/* Copyright (C) 1996 Xavier Leroy (Xavier.Leroy@inria.fr)              */
/*                                                                      */
/* This program is free software; you can redistribute it and/or        */
/* modify it under the terms of the GNU Library General Public License  */
/* as published by the Free Software Foundation; either version 2       */
/* of the License, or (at your option) any later version.               */
/*                                                                      */
/* This program is distributed in the hope that it will be useful,      */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU Library General Public License for more details.                 */

/* Semaphores a la POSIX 1003.1b */

#include <errno.h>
#include "pthread.h"
#include "semaphore.h"
#include "internals.h"
#include "spinlock.h"
#include "restart.h"
#include "queue.h"
#include <shlib-compat.h>

int __new_sem_init(sem_t *sem, int pshared, unsigned int value)
{
  if (value > SEM_VALUE_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (pshared) {
    errno = ENOSYS;
    return -1;
  }
  __pthread_init_lock((pthread_spinlock_t *) &sem->__sem_lock);
  sem->__sem_value = value;
  sem->__sem_waiting = NULL;
  return 0;
}

/* Function called by pthread_cancel to remove the thread from
   waiting inside __new_sem_wait. */

static int new_sem_extricate_func(void *obj, pthread_descr th)
{
  volatile pthread_descr self = thread_self();
  sem_t *sem = obj;
  int did_remove = 0;

  __pthread_lock((pthread_spinlock_t *) &sem->__sem_lock, self);
  did_remove = remove_from_queue(&sem->__sem_waiting, th);
  __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);

  return did_remove;
}

int __new_sem_wait(sem_t * sem)
{
  volatile pthread_descr self = thread_self();
  pthread_extricate_if extr;
  int already_canceled = 0;

  /* Set up extrication interface */
  extr.pu_object = sem;
  extr.pu_extricate_func = new_sem_extricate_func;

  __pthread_lock((pthread_spinlock_t *) &sem->__sem_lock, self);
  if (sem->__sem_value > 0) {
    sem->__sem_value--;
    __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
    return 0;
  }
  /* Register extrication interface */
  __pthread_set_own_extricate_if(self, &extr);
  /* Enqueue only if not already cancelled. */
  if (!(THREAD_GETMEM(self, p_canceled)
      && THREAD_GETMEM(self, p_cancelstate) == PTHREAD_CANCEL_ENABLE))
    enqueue(&sem->__sem_waiting, self);
  else
    already_canceled = 1;
  __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);

  if (already_canceled) {
    __pthread_set_own_extricate_if(self, 0);
    pthread_exit(PTHREAD_CANCELED);
  }

  /* Wait for sem_post or cancellation, or fall through if already canceled */
  suspend(self);
  __pthread_set_own_extricate_if(self, 0);

  /* Terminate only if the wakeup came from cancellation. */
  /* Otherwise ignore cancellation because we got the semaphore. */

  if (THREAD_GETMEM(self, p_woken_by_cancel)
      && THREAD_GETMEM(self, p_cancelstate) == PTHREAD_CANCEL_ENABLE) {
    THREAD_SETMEM(self, p_woken_by_cancel, 0);
    pthread_exit(PTHREAD_CANCELED);
  }
  /* We got the semaphore */
  return 0;
}

int __new_sem_trywait(sem_t * sem)
{
  int retval;

  __pthread_lock((pthread_spinlock_t *) &sem->__sem_lock, NULL);
  if (sem->__sem_value == 0) {
    errno = EAGAIN;
    retval = -1;
  } else {
    sem->__sem_value--;
    retval = 0;
  }
  __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
  return retval;
}

int __new_sem_post(sem_t * sem)
{
  pthread_descr self = thread_self();
  pthread_descr th;
  struct pthread_request request;

  if (THREAD_GETMEM(self, p_in_sighandler) == NULL) {
    __pthread_lock((pthread_spinlock_t *) &sem->__sem_lock, self);
    if (sem->__sem_waiting == NULL) {
      if (sem->__sem_value >= SEM_VALUE_MAX) {
        /* Overflow */
        errno = ERANGE;
        __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
        return -1;
      }
      sem->__sem_value++;
      __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
    } else {
      th = dequeue(&sem->__sem_waiting);
      __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
      restart(th);
    }
  } else {
    /* If we're in signal handler, delegate post operation to
       the thread manager. */
    if (__pthread_manager_request < 0) {
      if (__pthread_initialize_manager() < 0) {
        errno = EAGAIN;
        return -1;
      }
    }
    request.req_kind = REQ_POST;
    request.req_args.post = sem;
    __libc_write(__pthread_manager_request,
                 (char *) &request, sizeof(request));
  }
  return 0;
}

int __new_sem_getvalue(sem_t * sem, int * sval)
{
  *sval = sem->__sem_value;
  return 0;
}

int __new_sem_destroy(sem_t * sem)
{
  if (sem->__sem_waiting != NULL) {
    __set_errno (EBUSY);
    return -1;
  }
  return 0;
}

sem_t *sem_open(const char *name, int oflag, ...)
{
  __set_errno (ENOSYS);
  return SEM_FAILED;
}

int sem_close(sem_t *sem)
{
  __set_errno (ENOSYS);
  return -1;
}

int sem_unlink(const char *name)
{
  __set_errno (ENOSYS);
  return -1;
}

int sem_timedwait(sem_t *sem, const struct timespec *abstime)
{
  pthread_descr self = thread_self();
  pthread_extricate_if extr;
  int already_canceled = 0;
  int was_signalled = 0;
  sigjmp_buf jmpbuf;
  sigset_t unblock;
  sigset_t initial_mask;

  __pthread_lock((pthread_spinlock_t *) &sem->__sem_lock, self);
  if (sem->__sem_value > 0) {
    --sem->__sem_value;
    __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
    return 0;
  }

  if (abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000) {
    /* The standard requires that if the function would block and the
       time value is illegal, the function returns with an error.  */
    __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);
    return EINVAL;
  }

  /* Set up extrication interface */
  extr.pu_object = sem;
  extr.pu_extricate_func = new_sem_extricate_func;

  /* Register extrication interface */
  __pthread_set_own_extricate_if(self, &extr);
  /* Enqueue only if not already cancelled. */
  if (!(THREAD_GETMEM(self, p_canceled)
      && THREAD_GETMEM(self, p_cancelstate) == PTHREAD_CANCEL_ENABLE))
    enqueue(&sem->__sem_waiting, self);
  else
    already_canceled = 1;
  __pthread_spin_unlock((pthread_spinlock_t *) &sem->__sem_lock);

  if (already_canceled) {
    __pthread_set_own_extricate_if(self, 0);
    pthread_exit(PTHREAD_CANCELED);
  }

  /* Set up a longjmp handler for the restart signal, unblock
     the signal and sleep. */

  if (sigsetjmp(jmpbuf, 1) == 0) {
    THREAD_SETMEM(self, p_signal_jmp, &jmpbuf);
    THREAD_SETMEM(self, p_signal, 0);
    /* Unblock the restart signal */
    sigemptyset(&unblock);
    sigaddset(&unblock, __pthread_sig_restart);
    sigprocmask(SIG_UNBLOCK, &unblock, &initial_mask);

    while (1) {
        struct timeval now;
        struct timespec reltime;

        /* Compute a time offset relative to now.  */
        __gettimeofday (&now, NULL);
        reltime.tv_nsec = abstime->tv_nsec - now.tv_usec * 1000;
        reltime.tv_sec = abstime->tv_sec - now.tv_sec;
        if (reltime.tv_nsec < 0) {
          reltime.tv_nsec += 1000000000;
          reltime.tv_sec -= 1;
        }

        /* Sleep for the required duration. If woken by a signal,
           resume waiting as required by Single Unix Specification.  */
        if (reltime.tv_sec < 0 || __libc_nanosleep(&reltime, NULL) == 0)
          break;
      }

    /* Block the restart signal again */
    sigprocmask(SIG_SETMASK, &initial_mask, NULL);
    was_signalled = 0;
  } else {
    was_signalled = 1;
  }
  THREAD_SETMEM(self, p_signal_jmp, NULL);

  /* Now was_signalled is true if we exited the above code
     due to the delivery of a restart signal.  In that case,
     everything is cool. We have been removed from the queue
     by the other thread, and consumed its signal.

     Otherwise we this thread woke up spontaneously, or due to a signal other
     than restart. The next thing to do is to try to remove the thread
     from the queue. This may fail due to a race against another thread
     trying to do the same. In the failed case, we know we were signalled,
     and we may also have to consume a restart signal. */

  if (!was_signalled) {
    int was_on_queue;

    /* __pthread_lock will queue back any spurious restarts that
       may happen to it. */

    __pthread_lock((pthread_spinlock_t *)&sem->__sem_lock, self);
    was_on_queue = remove_from_queue(&sem->__sem_waiting, self);
    __pthread_spin_unlock((pthread_spinlock_t *)&sem->__sem_lock);

    if (was_on_queue) {
      __pthread_set_own_extricate_if(self, 0);
      return ETIMEDOUT;
    }

    /* Eat the outstanding restart() from the signaller */
    suspend(self);
  }
 __pthread_set_own_extricate_if(self, 0);

  /* Terminate only if the wakeup came from cancellation. */
  /* Otherwise ignore cancellation because we got the semaphore. */

  if (THREAD_GETMEM(self, p_woken_by_cancel)
      && THREAD_GETMEM(self, p_cancelstate) == PTHREAD_CANCEL_ENABLE) {
    THREAD_SETMEM(self, p_woken_by_cancel, 0);
    pthread_exit(PTHREAD_CANCELED);
  }
  /* We got the semaphore */
  return 0;
}


versioned_symbol (libpthread, __new_sem_init, sem_init, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_wait, sem_wait, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_trywait, sem_trywait, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_post, sem_post, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_getvalue, sem_getvalue, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_destroy, sem_destroy, GLIBC_2_1);
