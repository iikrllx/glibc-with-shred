/* Copyright (C) 1996, 1997 Free Software Foundation, Inc.
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
 * Never include this file directly; use <sys/ioctl.h> instead.
 */

#ifndef _BITS_IOCTLS_H
#define _BITS_IOCTLS_H 1

/* Use the definitions from the kernel header files.  */
#include <asm/ioctls.h>
#include <kernel_termios.h>

/* Oh well, this is necessary since the kernel data structure is
   different from the user-level version.  */
#undef  TCGETS
#undef  TCSETS
#undef  TCSETSW
#undef  TCSETSF
#define TCGETS	_IOR ('T', 8, char[36])
#define TCSETS	_IOW ('T', 9, char[36])
#define TCSETSW	_IOW ('T', 10, char[36])
#define TCSETSF	_IOW ('T', 11, char[36])

#include <linux/sockios.h>

#endif /* bits/ioctls.h  */
