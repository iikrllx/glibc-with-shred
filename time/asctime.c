/* Copyright (C) 1991, 1993, 1995, 1996, 1997 Free Software Foundation, Inc.
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

#include "../locale/localeinfo.h"
#include <errno.h>
#include <stdio.h>
#include <time.h>


static const char format[] = "%.3s %.3s%3d %.2d:%.2d:%.2d %d\n";
static char result[	         3+1+ 3+1+20+1+20+1+20+1+20+1+20+1 + 1];

/* Returns a string of the form "Day Mon dd hh:mm:ss yyyy\n"
   which is the representation of TP in that form.  */
char *
asctime (const struct tm *tp)
{
  return __asctime_r (tp, result);
}


char *
__asctime_r (const struct tm *tp, char *buf)
{
  if (tp == NULL)
    {
      __set_errno (EINVAL);
      return NULL;
    }

  if (sprintf (buf, format,
	       (tp->tm_wday < 0 || tp->tm_wday >= 7 ?
		"???" : _NL_CURRENT (LC_TIME, ABDAY_1 + tp->tm_wday)),
	       (tp->tm_mon < 0 || tp->tm_mon >= 12 ?
		"???" : _NL_CURRENT (LC_TIME, ABMON_1 + tp->tm_mon)),
	       tp->tm_mday, tp->tm_hour, tp->tm_min,
	       tp->tm_sec, 1900 + tp->tm_year) < 0)
    return NULL;

  return buf;
}
weak_alias (__asctime_r, asctime_r)
