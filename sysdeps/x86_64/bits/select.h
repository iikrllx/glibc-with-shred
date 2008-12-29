/* Copyright (C) 1997, 1998, 1999, 2001, 2008 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _SYS_SELECT_H
# error "Never use <bits/select.h> directly; include <sys/select.h> instead."
#endif

#include <bits/wordsize.h>


#if defined __GNUC__ && __GNUC__ >= 2

# if __WORDSIZE == 64
#  define __FD_ZERO_STOS "stosq"
#  define __FD_SET_BTS "btsq"
#  define __FD_CLR_BTR "btrq"
#  define __FD_ISSET_BT "btq"
# else
#  define __FD_ZERO_STOS "stosl"
#  define __FD_SET_BTS "btsl"
#  define __FD_CLR_BTR "btrl"
#  define __FD_ISSET_BT "btl"
# endif

# define __FD_ZERO(fdsp) \
  do {									      \
    int __d0, __d1;							      \
    __asm__ __volatile__ ("cld; rep; " __FD_ZERO_STOS			      \
			  : "=c" (__d0), "=D" (__d1)			      \
			  : "a" (0), "0" (sizeof (fd_set)		      \
					  / sizeof (__fd_mask)),	      \
			    "1" (&__FDS_BITS (fdsp)[0])			      \
			  : "memory");					      \
  } while (0)

# define __FD_SET(fd, fdsp) \
  __asm__ __volatile__ (__FD_SET_BTS " %1,%0"				      \
			: "=m" (__FDS_BITS (fdsp)[__FDELT (fd)])	      \
			: "r" (((int) (fd)) % __NFDBITS)		      \
			: "cc","memory")
# define __FD_CLR(fd, fdsp) \
  __asm__ __volatile__ (__FD_CLR_BTR " %1,%0"				      \
			: "=m" (__FDS_BITS (fdsp)[__FDELT (fd)])	      \
			: "r" (((int) (fd)) % __NFDBITS)		      \
			: "cc","memory")
# define __FD_ISSET(fd, fdsp) \
  (__extension__							      \
   ({register char __result;						      \
     __asm__ __volatile__ (__FD_ISSET_BT " %1,%2 ; setcb %b0"		      \
			   : "=q" (__result)				      \
			   : "r" (((int) (fd)) % __NFDBITS),		      \
			     "m" (__FDS_BITS (fdsp)[__FDELT (fd)])	      \
			   : "cc");					      \
     __result; }))

#else	/* ! GNU CC */

/* We don't use `memset' because this would require a prototype and
   the array isn't too big.  */
# define __FD_ZERO(set)  \
  do {									      \
    unsigned int __i;							      \
    fd_set *__arr = (set);						      \
    for (__i = 0; __i < sizeof (fd_set) / sizeof (__fd_mask); ++__i)	      \
      __FDS_BITS (__arr)[__i] = 0;					      \
  } while (0)
# define __FD_SET(d, set)    (__FDS_BITS (set)[__FDELT (d)] |= __FDMASK (d))
# define __FD_CLR(d, set)    (__FDS_BITS (set)[__FDELT (d)] &= ~__FDMASK (d))
# define __FD_ISSET(d, set)  (__FDS_BITS (set)[__FDELT (d)] & __FDMASK (d))

#endif	/* GNU CC */
