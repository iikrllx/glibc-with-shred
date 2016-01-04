/* libc-internal interface for mutex locks.  NPTL version.
   Copyright (C) 1996-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <http://www.gnu.org/licenses/>.  */

#ifndef _LIBC_LOCK_H
#define _LIBC_LOCK_H 1

#include <pthread.h>
#define __need_NULL
#include <stddef.h>


/* Mutex type.  */
#if defined _LIBC || defined _IO_MTSAFE_IO
# if (!IS_IN (libc) && !IS_IN (libpthread)) || !defined _LIBC
typedef struct { pthread_mutex_t mutex; } __libc_lock_recursive_t;
# else
typedef struct { int lock; int cnt; void *owner; } __libc_lock_recursive_t;
# endif
#else
typedef struct __libc_lock_recursive_opaque__ __libc_lock_recursive_t;
#endif

/* Define a lock variable NAME with storage class CLASS.  The lock must be
   initialized with __libc_lock_init before it can be used (or define it
   with __libc_lock_define_initialized, below).  Use `extern' for CLASS to
   declare a lock defined in another module.  In public structure
   definitions you must use a pointer to the lock structure (i.e., NAME
   begins with a `*'), because its storage size will not be known outside
   of libc.  */
#define __libc_lock_define_recursive(CLASS,NAME) \
  CLASS __libc_lock_recursive_t NAME;

/* Define an initialized recursive lock variable NAME with storage
   class CLASS.  */
#if defined _LIBC && (IS_IN (libc) || IS_IN (libpthread))
# define __libc_lock_define_initialized_recursive(CLASS, NAME) \
  CLASS __libc_lock_recursive_t NAME = _LIBC_LOCK_RECURSIVE_INITIALIZER;
# define _LIBC_LOCK_RECURSIVE_INITIALIZER \
  { LLL_LOCK_INITIALIZER, 0, NULL }
#else
# define __libc_lock_define_initialized_recursive(CLASS,NAME) \
  CLASS __libc_lock_recursive_t NAME = _LIBC_LOCK_RECURSIVE_INITIALIZER;
# define _LIBC_LOCK_RECURSIVE_INITIALIZER \
  {PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP}
#endif

/* Initialize a recursive mutex.  */
#if defined _LIBC && (IS_IN (libc) || IS_IN (libpthread))
# define __libc_lock_init_recursive(NAME) \
  ((void) ((NAME) = (__libc_lock_recursive_t) _LIBC_LOCK_RECURSIVE_INITIALIZER))
#else
# define __libc_lock_init_recursive(NAME) \
  do {									      \
    if (__pthread_mutex_init != NULL)					      \
      {									      \
	pthread_mutexattr_t __attr;					      \
	__pthread_mutexattr_init (&__attr);				      \
	__pthread_mutexattr_settype (&__attr, PTHREAD_MUTEX_RECURSIVE_NP);    \
	__pthread_mutex_init (&(NAME).mutex, &__attr);			      \
	__pthread_mutexattr_destroy (&__attr);				      \
      }									      \
  } while (0)
#endif

/* Finalize recursive named lock.  */
#if defined _LIBC && (IS_IN (libc) || IS_IN (libpthread))
# define __libc_lock_fini_recursive(NAME) ((void) 0)
#else
# define __libc_lock_fini_recursive(NAME) \
  __libc_maybe_call (__pthread_mutex_destroy, (&(NAME).mutex), 0)
#endif

/* Lock the recursive named lock variable.  */
#if defined _LIBC && (IS_IN (libc) || IS_IN (libpthread))
# define __libc_lock_lock_recursive(NAME) \
  do {									      \
    void *self = THREAD_SELF;						      \
    if ((NAME).owner != self)						      \
      {									      \
	lll_lock ((NAME).lock, LLL_PRIVATE);				      \
	(NAME).owner = self;						      \
      }									      \
    ++(NAME).cnt;							      \
  } while (0)
#else
# define __libc_lock_lock_recursive(NAME) \
  __libc_maybe_call (__pthread_mutex_lock, (&(NAME).mutex), 0)
#endif

/* Try to lock the recursive named lock variable.  */
#if defined _LIBC && (IS_IN (libc) || IS_IN (libpthread))
# define __libc_lock_trylock_recursive(NAME) \
  ({									      \
    int result = 0;							      \
    void *self = THREAD_SELF;						      \
    if ((NAME).owner != self)						      \
      {									      \
	if (lll_trylock ((NAME).lock) == 0)				      \
	  {								      \
	    (NAME).owner = self;					      \
	    (NAME).cnt = 1;						      \
	  }								      \
	else								      \
	  result = EBUSY;						      \
      }									      \
    else								      \
      ++(NAME).cnt;							      \
    result;								      \
  })
#else
# define __libc_lock_trylock_recursive(NAME) \
  __libc_maybe_call (__pthread_mutex_trylock, (&(NAME).mutex), 0)
#endif

/* Unlock the recursive named lock variable.  */
#if defined _LIBC && (IS_IN (libc) || IS_IN (libpthread))
/* We do no error checking here.  */
# define __libc_lock_unlock_recursive(NAME) \
  do {									      \
    if (--(NAME).cnt == 0)						      \
      {									      \
	(NAME).owner = NULL;						      \
	lll_unlock ((NAME).lock, LLL_PRIVATE);				      \
      }									      \
  } while (0)
#else
# define __libc_lock_unlock_recursive(NAME) \
  __libc_maybe_call (__pthread_mutex_unlock, (&(NAME).mutex), 0)
#endif

/* Note that for I/O cleanup handling we are using the old-style
   cancel handling.  It does not have to be integrated with C++ since
   no C++ code is called in the middle.  The old-style handling is
   faster and the support is not going away.  */
extern void _pthread_cleanup_push_defer (struct _pthread_cleanup_buffer *buffer,
					 void (*routine) (void *), void *arg);
extern void _pthread_cleanup_pop_restore (struct _pthread_cleanup_buffer *buffer,
					  int execute);

/* Start critical region with cleanup.  */
#define __libc_cleanup_region_start(DOIT, FCT, ARG) \
  { struct _pthread_cleanup_buffer _buffer;				      \
    int _avail;								      \
    if (DOIT) {								      \
      _avail = PTFAVAIL (_pthread_cleanup_push_defer);			      \
      if (_avail) {							      \
	__libc_ptf_call_always (_pthread_cleanup_push_defer, (&_buffer, FCT,  \
							      ARG));	      \
      } else {								      \
	_buffer.__routine = (FCT);					      \
	_buffer.__arg = (ARG);						      \
      }									      \
    } else {								      \
      _avail = 0;							      \
    }

/* End critical region with cleanup.  */
#define __libc_cleanup_region_end(DOIT) \
    if (_avail) {							      \
      __libc_ptf_call_always (_pthread_cleanup_pop_restore, (&_buffer, DOIT));\
    } else if (DOIT)							      \
      _buffer.__routine (_buffer.__arg);				      \
  }


/* Hide the definitions which are only supposed to be used inside libc in
   a separate file.  This file is not present in the installation!  */
#ifdef _LIBC
# include "libc-lockP.h"
#endif

#endif	/* libc-lock.h */
