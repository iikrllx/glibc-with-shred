/* Copyright (C) 1991, 1995 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <stdarg.h>
#include <stdio.h>

#ifdef USE_IN_LIBIO
# define __vsnprintf _IO_vsnprintf
#endif

/* Write formatted output into S, according to the format
   string FORMAT, writing no more than MAXLEN characters.  */
/* VARARGS3 */
int
__snprintf (s, maxlen, format)
      char *s;
      size_t maxlen;
      const char *format;
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = __vsnprintf (s, maxlen, format, arg);
  va_end (arg);

  return done;
}
weak_alias (__snprintf, snprintf)
