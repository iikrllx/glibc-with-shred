/* Copyright (C) 1991, 1997 Free Software Foundation, Inc.
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

#include <sys/time.h>
#include <unistd.h>

/* Set an alarm to go off (generating a SIGALRM signal) in VALUE microseconds.
   If INTERVAL is nonzero, when the alarm goes off, the timer is reset to go
   off every INTERVAL microseconds thereafter.

   Returns the number of microseconds remaining before the alarm.  */
unsigned int
ualarm (value, interval)
     unsigned int value;
     unsigned int interval;
{
  struct itimerval timer, otimer;

  timer.it_value.tv_sec = 0;
  timer.it_value.tv_usec = value;
  timer.it_interval.tv_sec = 0;
  timer.it_interval.tv_usec = interval;

  if (setitimer (ITIMER_REAL, &timer, &otimer) < 0)
    return -1;

  return (otimer.it_value.tv_sec * 1000000) + otimer.it_value.tv_usec;
}
