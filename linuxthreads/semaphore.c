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
  __pthread_init_lock((struct _pthread_fastlock *) &sem->__sem_lock);
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

  __pthread_lock((struct _pthread_fastlock *) &sem->__sem_lock, self);
  did_remove = remove_from_queue(&sem->__sem_waiting, th);
  __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);

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

  __pthread_lock((struct _pthread_fastlock *) &sem->__sem_lock, self);
  if (sem->__sem_value > 0) {
    sem->__sem_value--;
    __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);
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
  __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);

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

  __pthread_lock((struct _pthread_fastlock *) &sem->__sem_lock, NULL);
  if (sem->__sem_value == 0) {
    errno = EAGAIN;
    retval = -1;
  } else {
    sem->__sem_value--;
    retval = 0;
  }
  __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);
  return retval;
}

int __new_sem_post(sem_t * sem)
{
  pthread_descr self = thread_self();
  pthread_descr th;
  struct pthread_request request;

  if (THREAD_GETMEM(self, p_in_sighandler) == NULL) {
    __pthread_lock((struct _pthread_fastlock *) &sem->__sem_lock, self);
    if (sem->__sem_waiting == NULL) {
      if (sem->__sem_value >= SEM_VALUE_MAX) {
        /* Overflow */
        errno = ERANGE;
        __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);
        return -1;
      }
      sem->__sem_value++;
      __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);
    } else {
      th = dequeue(&sem->__sem_waiting);
      __pthread_unlock((struct _pthread_fastlock *) &sem->__sem_lock);
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

versioned_symbol (libpthread, __new_sem_init, sem_init, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_wait, sem_wait, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_trywait, sem_trywait, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_post, sem_post, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_getvalue, sem_getvalue, GLIBC_2_1);
versioned_symbol (libpthread, __new_sem_destroy, sem_destroy, GLIBC_2_1);
