/* Copyright (C) 1991, 1995, 1996, 1997, 2002 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sys/wait.h>
#include <errno.h>
#include <sys/resource.h>
#include <stddef.h>
#include <sysdep-cancel.h>

/* Wait for a child to die.  When one does, put its status in *STAT_LOC
   and return its process ID.  For errors, return (pid_t) -1.  */
__pid_t
__libc_wait (__WAIT_STATUS_DEFN stat_loc)
{
  if (SINGLE_THREAD_P)
    return INLINE_SYSCALL (wait4, 4, WAIT_ANY, stat_loc, 0,
			   (struct rusage *) NULL);

  int oldtype = LIBC_CANCEL_ASYNC ();

  int result = INLINE_SYSCALL (wait4, 4, WAIT_ANY, stat_loc, 0,
			       (struct rusage *) NULL);

  LIBC_CANCEL_RESET (oldtype);

  return result;
}

weak_alias (__libc_wait, __wait)
weak_alias (__libc_wait, wait)
