/* Copyright (C) 2011-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Chris Metcalf <cmetcalf@tilera.com>, 2011.

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
   <http://www.gnu.org/licenses/>.  */

#include <fcntl.h>
#include <sys/types.h>
#include <sysdep-cancel.h>

#undef	creat

/* Create FILE with protections MODE.  */
int
creat (const char *file, mode_t mode)
{
  return __open (file, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

/* __open handles cancellation.  */
LIBC_CANCEL_HANDLED ();

#if __WORDSIZE == 64
weak_alias (creat, creat64)
#endif
