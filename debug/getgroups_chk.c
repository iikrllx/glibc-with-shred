/* Copyright (C) 2005, 2008 Free Software Foundation, Inc.
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

#include <errno.h>
#include <unistd.h>


int
__getgroups_chk (int size, __gid_t list[], size_t listlen)
{
  if (__builtin_expect (size < 0, 0))
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (__builtin_expect (size * sizeof (__gid_t) > listlen, 0))
    __chk_fail ();

  return __getgroups (size, list);
}
