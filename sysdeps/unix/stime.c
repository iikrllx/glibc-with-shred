/* Copyright (C) 1992, 1996, 1997, 2001 Free Software Foundation, Inc.
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

#include <errno.h>
#include <stddef.h>		/* For NULL.  */
#include <sys/time.h>
#include <time.h>

/* Set the system clock to *WHEN.  */

int
stime (when)
     const time_t *when;
{
  struct timeval tv;

  if (when == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }

  tv.tv_sec = *when;
  tv.tv_usec = 0;
  return __settimeofday (&tv, (struct timezone *) 0);
}
