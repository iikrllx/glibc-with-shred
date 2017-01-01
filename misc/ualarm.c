/* Copyright (C) 1991-2017 Free Software Foundation, Inc.
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

#include <errno.h>
#include <unistd.h>

/* Set an alarm to go off (generating a SIGALRM signal) in VALUE microseconds.
   If INTERVAL is nonzero, when the alarm goes off, the timer is reset to go
   off every INTERVAL microseconds thereafter.

   Returns the number of microseconds remaining before the alarm.  */
useconds_t
ualarm (useconds_t value, useconds_t interval)
{
  __set_errno (ENOSYS);
  return -1;
}

stub_warning (ualarm)
