/* Copyright (C) 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <unistd.h>

/* is there a reason *NOT* to include <sys/id.h>? */
/* If so #define ID_EFFECTIVE and ID_REAL         */
#include <sys/id.h>


extern int setgidx (int mask, gid_t gid);

int
__setregid (gid_t rgid, gid_t egid)
{
  int res;

  if (rgid == egid)
    return setgidx (ID_EFFECTIVE | ID_REAL, egid);

  res = setgidx (ID_REAL, rgid);
  if (res == 0)
    res = setgidx (ID_EFFECTIVE, egid);

  return res;
}
strong_alias (__setregid, setregid)
