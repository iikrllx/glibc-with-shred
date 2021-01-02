/* Implement pthread_rwlock_clockrdlock.

   Copyright (C) 2019-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "pthread_rwlock_common.c"

/* See pthread_rwlock_common.c.  */
int
__pthread_rwlock_clockrdlock64 (pthread_rwlock_t *rwlock, clockid_t clockid,
                                const struct __timespec64 *abstime)
{
  return __pthread_rwlock_rdlock_full64 (rwlock, clockid, abstime);
}

#if __TIMESIZE != 64
libpthread_hidden_def (__pthread_rwlock_clockrdlock64)

int
__pthread_rwlock_clockrdlock (pthread_rwlock_t *rwlock, clockid_t clockid,
                              const struct timespec *abstime)
{
  struct __timespec64 ts64 = valid_timespec_to_timespec64 (*abstime);

  return __pthread_rwlock_clockrdlock64 (rwlock, clockid, &ts64);
}
#endif
weak_alias (__pthread_rwlock_clockrdlock, pthread_rwlock_clockrdlock)
