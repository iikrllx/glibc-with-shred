/* BSD-compatible versions of getpgrp function.
   Copyright (C) 1991,92,94,95,96,97,2000,2002 Free Software Foundation, Inc.
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

#include <sys/types.h>

/* Don't include unistd.h because it declares a conflicting
   prototype for the POSIX.1 `getpgrp' function.  */
extern pid_t __getpgid (pid_t);
extern pid_t __getpgid_internal (pid_t);
extern pid_t __bsd_getpgrp (pid_t);

pid_t
__bsd_getpgrp (pid_t pid)
{
  return INTUSE(__getpgid) (pid);
}
