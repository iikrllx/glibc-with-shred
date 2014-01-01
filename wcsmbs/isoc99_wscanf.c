/* Copyright (C) 1991-2014 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.  */

#include <stdarg.h>
#include <stdio.h>
#include <libioP.h>
#include <wchar.h>


/* Read formatted input from stdin according to the format string FORMAT.  */
/* VARARGS1 */
int
__isoc99_wscanf (const wchar_t *format, ...)
{
  va_list arg;
  int done;

  _IO_acquire_lock_clear_flags2 (stdin);
  stdin->_flags2 |= _IO_FLAGS2_SCANF_STD;

  va_start (arg, format);
  done = _IO_vfwscanf (stdin, format, arg, NULL);
  va_end (arg);

  _IO_release_lock (stdin);
  return done;
}
