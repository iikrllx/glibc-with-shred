/* Copyright (C) 2007-2020 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <sched.h>
#include <sysdep.h>
#include <atomic.h>
#include <sysdep-vdso.h>
#include <sys/rseq.h>

static int
vsyscall_sched_getcpu (void)
{
  unsigned int cpu;
  int r = -1;
#ifdef HAVE_GETCPU_VSYSCALL
  r = INLINE_VSYSCALL (getcpu, 3, &cpu, NULL, NULL);
#else
  r = INLINE_SYSCALL_CALL (getcpu, &cpu, NULL, NULL);
#endif
  return r == -1 ? r : cpu;
}

#ifdef RSEQ_SIG
int
sched_getcpu (void)
{
  int cpu_id = atomic_load_relaxed (&__rseq_abi.cpu_id);

  return cpu_id >= 0 ? cpu_id : vsyscall_sched_getcpu ();
}
#else /* RSEQ_SIG */
int
sched_getcpu (void)
{
  return vsyscall_sched_getcpu ();
}
#endif /* RSEQ_SIG */
