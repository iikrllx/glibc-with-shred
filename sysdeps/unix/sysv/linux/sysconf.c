/* Get file-specific information about a file.  Linux version.
   Copyright (C) 2003 Free Software Foundation, Inc.
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

#include <sysdep.h>
#include <time.h>
#include <unistd.h>

static long int posix_sysconf (int name);

/* Define this first, so it can be inlined.  */
#define __sysconf static posix_sysconf
#include <sysdeps/posix/sysconf.c>


/* Get the value of the system variable NAME.  */
long int
__sysconf (int name)
{
  switch (name)
    {
#ifdef __NR_clock_getres
    case _SC_MONOTONIC_CLOCK:
      /* Check using the clock_getres system call.  */
      {
	struct timespec ts;
	INTERNAL_SYSCALL_DECL (err);
	int r = INTERNAL_SYSCALL (clock_getres, err, 2, CLOCK_MONOTONIC, &ts);
	return INTERNAL_SYSCALL_ERROR_P (r, err) ? 0 : 1;
      }
#endif

    default:
      return posix_sysconf (name);
    }
}
