/* errnos.h - error constants.  Linux specific version.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <linux/errno.h>

#ifndef __ASSEMBLER__
#if defined __USE_REENTRANT && (!defined _LIBC || defined _LIBC_REENTRANT)
/* Declare alias of `errno' variable so it is accessible even if macro
   with name `errno' is defined.  */
extern int __errno;

/* When using threads, errno is a per-thread value.  */
extern int *__errno_location __P ((void)) __attribute__ ((__const__));
#define errno	(*__errno_location ())

#endif
#endif
