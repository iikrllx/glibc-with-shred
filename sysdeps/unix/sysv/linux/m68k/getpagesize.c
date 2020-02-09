/* Copyright (C) 2000-2020 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Schwab <schwab@suse.de>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <https://www.gnu.org/licenses/>.  */

#include <unistd.h>
#include <sys/param.h>
#include <errno.h>

#include <ldsodefs.h>
#include <sysdep.h>
#include <sys/syscall.h>

/* Return the system page size.  */
int
__getpagesize (void)
{
  int result;

  if (GLRO(dl_pagesize) != 0)
    return GLRO(dl_pagesize);

  result = INTERNAL_SYSCALL_CALL (getpagesize);
  /* The only possible error is ENOSYS.  */
  if (!INTERNAL_SYSCALL_ERROR_P (result))
    return result;

  return 4096;
}
libc_hidden_def (__getpagesize)
weak_alias (__getpagesize, getpagesize)
