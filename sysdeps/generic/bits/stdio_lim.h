/* Stdio limits for non-POSIX systems.
   Copyright (C) 1994, 1997 Free Software Foundation, Inc.
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

#ifndef _STDIO_H
# error "Never include <bits/stdio_lim.h> directly; use <stdio.h> instead."
#endif

#define	L_tmpnam	1
#define	TMP_MAX		0

#ifdef __USE_POSIX
# define L_ctermid	1
# define L_cuserid	1
#endif

#define	FOPEN_MAX	16
#define	FILENAME_MAX	14
