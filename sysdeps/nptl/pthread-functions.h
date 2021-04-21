/* Copyright (C) 2003-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _PTHREAD_FUNCTIONS_H
#define _PTHREAD_FUNCTIONS_H	1

#include <pthread.h>
#include <setjmp.h>
#include <internaltypes.h>
#include <sysdep.h>

struct xid_command;

/* Data type shared with libc.  The libc uses it to pass on calls to
   the thread functions.  */
struct pthread_functions
{
  int (*ptr___pthread_cond_broadcast) (pthread_cond_t *);
  int (*ptr___pthread_cond_signal) (pthread_cond_t *);
  int (*ptr___pthread_cond_wait) (pthread_cond_t *, pthread_mutex_t *);
  int (*ptr___pthread_cond_timedwait) (pthread_cond_t *, pthread_mutex_t *,
				       const struct timespec *);
  int (*ptr___pthread_cond_broadcast_2_0) (pthread_cond_2_0_t *);
  int (*ptr___pthread_cond_signal_2_0) (pthread_cond_2_0_t *);
  int (*ptr___pthread_cond_wait_2_0) (pthread_cond_2_0_t *, pthread_mutex_t *);
  int (*ptr___pthread_cond_timedwait_2_0) (pthread_cond_2_0_t *,
					   pthread_mutex_t *,
					   const struct timespec *);
  void (*ptr___pthread_exit) (void *) __attribute__ ((__noreturn__));
  int (*ptr_pthread_mutex_destroy) (pthread_mutex_t *);
  int (*ptr_pthread_mutex_init) (pthread_mutex_t *,
				 const pthread_mutexattr_t *);
  int (*ptr_pthread_mutex_lock) (pthread_mutex_t *);
  int (*ptr_pthread_mutex_unlock) (pthread_mutex_t *);
  int (*ptr___pthread_setcancelstate) (int, int *);
  int (*ptr_pthread_setcanceltype) (int, int *);
  int (*ptr___pthread_rwlock_rdlock) (pthread_rwlock_t *);
  int (*ptr___pthread_rwlock_wrlock) (pthread_rwlock_t *);
  int (*ptr___pthread_rwlock_unlock) (pthread_rwlock_t *);
  int (*ptr___pthread_key_create) (pthread_key_t *, void (*) (void *));
  void *(*ptr___pthread_getspecific) (pthread_key_t);
  int (*ptr___pthread_setspecific) (pthread_key_t, const void *);
#define HAVE_PTR_NTHREADS
  unsigned int *ptr_nthreads;
  void (*ptr__nptl_deallocate_tsd) (void);
  int (*ptr__nptl_setxid) (struct xid_command *);
  void (*ptr_set_robust) (struct pthread *);
};

/* Variable in libc.so.  */
extern struct pthread_functions __libc_pthread_functions attribute_hidden;
extern int __libc_pthread_functions_init attribute_hidden;

#ifdef PTR_DEMANGLE
# define PTHFCT_CALL(fct, params) \
  ({ __typeof (__libc_pthread_functions.fct) __p;			      \
     __p = __libc_pthread_functions.fct;				      \
     PTR_DEMANGLE (__p);						      \
     __p params; })
#else
# define PTHFCT_CALL(fct, params) \
  __libc_pthread_functions.fct params
#endif

#endif	/* pthread-functions.h */
