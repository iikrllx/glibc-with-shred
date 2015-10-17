/* Basic platform-independent macro definitions for mutexes,
   thread-specific data and parameters for malloc.
   Copyright (C) 2003-2015 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _GENERIC_MALLOC_MACHINE_H
#define _GENERIC_MALLOC_MACHINE_H

#include <atomic.h>

#ifndef mutex_init /* No threads, provide dummy macros */

# define NO_THREADS

/* The mutex functions used to do absolutely nothing, i.e. lock,
   trylock and unlock would always just return 0.  However, even
   without any concurrently active threads, a mutex can be used
   legitimately as an `in use' flag.  To make the code that is
   protected by a mutex async-signal safe, these macros would have to
   be based on atomic test-and-set operations, for example. */
typedef int mutex_t;

# define mutex_init(m)          (*(m) = 0)
# define mutex_lock(m)          ({ *(m) = 1; 0; })
# define mutex_trylock(m)       (*(m) ? 1 : ((*(m) = 1), 0))
# define mutex_unlock(m)        (*(m) = 0)
# define MUTEX_INITIALIZER      (0)

#endif /* !defined mutex_init */

#ifndef atomic_full_barrier
# define atomic_full_barrier() __asm ("" ::: "memory")
#endif

#ifndef atomic_read_barrier
# define atomic_read_barrier() atomic_full_barrier ()
#endif

#ifndef atomic_write_barrier
# define atomic_write_barrier() atomic_full_barrier ()
#endif

#ifndef DEFAULT_TOP_PAD
# define DEFAULT_TOP_PAD 131072
#endif

#endif /* !defined(_GENERIC_MALLOC_MACHINE_H) */
