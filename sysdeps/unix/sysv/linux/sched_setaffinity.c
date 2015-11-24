/* Copyright (C) 2002-2015 Free Software Foundation, Inc.
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

#include <errno.h>
#include <sched.h>
#include <string.h>
#include <sysdep.h>
#include <unistd.h>
#include <sys/types.h>
#include <shlib-compat.h>


#ifdef __NR_sched_setaffinity

int
__sched_setaffinity_new (pid_t pid, size_t cpusetsize, const cpu_set_t *cpuset)
{
  int result = INLINE_SYSCALL (sched_setaffinity, 3, pid, cpusetsize, cpuset);

#ifdef RESET_VGETCPU_CACHE
  if (result != -1)
    RESET_VGETCPU_CACHE ();
#endif

  return result;
}
versioned_symbol (libc, __sched_setaffinity_new, sched_setaffinity,
		  GLIBC_2_3_4);


# if SHLIB_COMPAT (libc, GLIBC_2_3_3, GLIBC_2_3_4)
int
attribute_compat_text_section
__sched_setaffinity_old (pid_t pid, const cpu_set_t *cpuset)
{
  /* The old interface by default assumed a 1024 processor bitmap.  */
  return __sched_setaffinity_new (pid, 128, cpuset);
}
compat_symbol (libc, __sched_setaffinity_old, sched_setaffinity, GLIBC_2_3_3);
# endif
#else
# include <posix/sched_setaffinity.c>
#endif
