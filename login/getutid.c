/* Copyright (C) 1996-2022 Free Software Foundation, Inc.
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

#include <stdlib.h>
#include <utmp.h>


/* Local buffer to store the result.  */
libc_freeres_ptr (static struct utmp *buffer);

struct utmp *
__getutid (const struct utmp *id)
{
  struct utmp *result;

  if (buffer == NULL)
    {
      buffer = (struct utmp *) malloc (sizeof (struct utmp));
      if (buffer == NULL)
        return NULL;
    }
  if (__getutid_r (id, buffer, &result) < 0)
    return NULL;

  return result;
}
libc_hidden_def (__getutid)
weak_alias (__getutid, getutid)
