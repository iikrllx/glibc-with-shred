/* High precision, low overhead timing functions.  sparc64 version.
   Copyright (C) 2001-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by David S. Miller <davem@redhat.com>, 2001.

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

#ifndef _HP_TIMING_H
#define _HP_TIMING_H	1

#include <string.h>
#include <sys/param.h>
#include <_itoa.h>

#define HP_TIMING_AVAIL		(1)
#define HP_TIMING_INLINE	(1)

typedef unsigned long int hp_timing_t;

#define HP_TIMING_NOW(Var) __asm__ __volatile__ ("rd %%tick, %0" : "=r" (Var))

#define HP_TIMING_DIFF_INIT() \
  do {									      \
    int __cnt = 5;							      \
    GLRO(dl_hp_timing_overhead) = ~0ull;				      \
    do									      \
      {									      \
	hp_timing_t __t1, __t2;						      \
	HP_TIMING_NOW (__t1);						      \
	HP_TIMING_NOW (__t2);						      \
	if (__t2 - __t1 < GLRO(dl_hp_timing_overhead))			      \
	  GLRO(dl_hp_timing_overhead) = __t2 - __t1;			      \
      }									      \
    while (--__cnt > 0);						      \
  } while (0)

#define HP_TIMING_DIFF(Diff, Start, End)	(Diff) = ((End) - (Start))

#define HP_TIMING_ACCUM_NT(Sum, Diff)	(Sum) += (Diff)

#define HP_TIMING_PRINT(Buf, Len, Val) \
  do {									      \
    char __buf[20];							      \
    char *__cp = _itoa (Val, __buf + sizeof (__buf), 10, 0);		      \
    int __len = (Len);							      \
    char *__dest = (Buf);						      \
    while (__len-- > 0 && __cp < __buf + sizeof (__buf))		      \
      *__dest++ = *__cp++;						      \
    memcpy (__dest, " clock cycles", MIN (__len, sizeof (" clock cycles")));  \
  } while (0)

#endif	/* hp-timing.h */
