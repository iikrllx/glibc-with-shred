/* Macros to swap the order of bytes in integer values.  s390 version.
   Copyright (C) 2000 Free Software Foundation, Inc.
   Contributed by Martin Schwidefsky (schwidefsky@de.ibm.com).
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

#if !defined _BYTESWAP_H && !defined _NETINET_IN_H
# error "Never use <bits/byteswap.h> directly; include <byteswap.h> instead."
#endif

#define __bswap_constant_16(x) \
     ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

/* Swap bytes in 16 bit value. */
#if defined __GNUC__ && __GNUC__ >= 2
# define __bswap_16(x) \
     (__extension__							      \
      ({ unsigned short int __v;		                              \
	 if (__builtin_constant_p (x))					      \
	   __v = __bswap_constant_16 (x);				      \
	 else {								      \
           unsigned short int __tmp = (unsigned short int) (x);               \
           __asm__ __volatile__ (                                             \
              "sr   %0,%0\n"                                                  \
              "la   1,%1\n"                                                   \
              "icm  %0,2,1(1)\n"                                              \
              "ic   %0,0(1)"                                                  \
              : "=&d" (__v) : "m" (__tmp) : "1");                             \
         }                                                                    \
	 __v; }))
#else
/* This is better than nothing.  */
#define __bswap_16(x) __bswap_constant_16 (x)
#endif

/* Swap bytes in 32 bit value.  */
#define __bswap_constant_32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#if defined __GNUC__ && __GNUC__ >= 2
#  define __bswap_32(x) \
     (__extension__							      \
      ({ unsigned int __v;				                      \
	 if (__builtin_constant_p (x))					      \
	   __v = __bswap_constant_32 (x);				      \
	 else {								      \
           unsigned int __tmp = (unsigned int) (x);                           \
           __asm__ __volatile__ (                                             \
              "la    1,%1\n"                                                  \
              "icm   %0,8,3(1)\n"                                             \
              "icm   %0,4,2(1)\n"                                             \
              "icm   %0,2,1(1)\n"                                             \
              "ic    %0,0(1)"                                                 \
              : "=&d" (__v) : "m" (__tmp) : "1");                             \
         }                                                                    \
	 __v; }))
#else
# define __bswap_32(x) __bswap_constant_32 (x)
#endif

#if defined __GNUC__ && __GNUC__ >= 2
/* Swap bytes in 64 bit value.  */
# define __bswap_64(x) \
  __extension__						\
  ({ union { unsigned long long int __ll;		\
	     unsigned long int __l[2]; } __w, __r;	\
     __w.__ll = (x);					\
     __r.__l[0] = __bswap_32 (__w.__l[1]);		\
     __r.__l[1] = __bswap_32 (__w.__l[0]);		\
     __r.__ll; })
#endif
