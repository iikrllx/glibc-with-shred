/* System-dependent timing definitions.  Linux version.
   Copyright (C) 1996 Free Software Foundation, Inc.
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

#ifdef __need_timeval
# undef __need_timeval
# ifndef _STRUCT_TIMEVAL
#  define _STRUCT_TIMEVAL	1
/* A time value that is accurate to the nearest
   microsecond but also has a range of years.  */
struct timeval
  {
    time_t tv_sec;		/* Seconds.  */
    time_t tv_usec;		/* Microseconds.  */
  };
# endif	/* struct timeval */
#endif	/* need timeval */


#ifndef _TIMEBITS_H
# define _TIMEBITS_H	1

/* ISO/IEC 9899:1990 7.12.1: <time.h>
   The macro `CLOCKS_PER_SEC' is the number per second of the value
   returned by the `clock' function. */
/* CAE XSH, Issue 4, Version 2: <time.h>
   The value of CLOCKS_PER_SEC is required to be 1 million on all
   XSI-conformant systems. */
# define CLOCKS_PER_SEC  1000000

#endif	/* timebits.h */
