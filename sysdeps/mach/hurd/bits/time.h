/* System-dependent timing definitions.  Hurd version.
   Copyright (C) 1996, 1997, 1999, 2000 Free Software Foundation, Inc.
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

/*
 * Never include this file directly; use <time.h> instead.
 */

#ifndef __need_timeval
# ifndef _BITS_TIME_H
#  define _BITS_TIME_H	1

/* ISO/IEC 9899:1990 7.12.1: <time.h>
   The macro `CLOCKS_PER_SEC' is the number per second of the value
   returned by the `clock' function. */
/* CAE XSH, Issue 4, Version 2: <time.h>
   The value of CLOCKS_PER_SEC is required to be 1 million on all
   XSI-conformant systems. */
#  define CLOCKS_PER_SEC  1000000

#  ifndef __STRICT_ANSI__
/* Even though CLOCKS_PER_SEC has such a strange value CLK_TCK
   presents the real value for clock ticks per second for the system.
   This value is determined at runtime.  */
#   define CLK_TCK __libc_clk_tck()
extern int __libc_clk_tck (void) __attribute__ ((__const__));
#  endif

/* Clock ID used in clock and timer functions.  */
typedef int __clockid_t;

/* Timer ID returned by `timer_create'.  */
typedef int __timer_t;

#  ifdef __USE_POSIX199309
/* Identifier for system-wide realtime clock.  */
#   define CLOCK_REALTIME	0

/* Flag to indicate time is absolute.  */
#   define TIMER_ABSTIME	1
#  endif

# endif	/* bits/time.h */
#endif


#ifdef __need_timeval
# undef __need_timeval
# ifndef _STRUCT_TIMEVAL
#  define _STRUCT_TIMEVAL	1
#  include <bits/types.h>

/* A time value that is accurate to the nearest
   microsecond but also has a range of years.  */
struct timeval
  {
    __time_t tv_sec;		/* Seconds.  */
    __suseconds_t tv_usec;	/* Microseconds.  */
  };
# endif	/* struct timeval */
#endif	/* need timeval */
