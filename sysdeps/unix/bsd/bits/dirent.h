/* Directory entry structure `struct dirent'.  4.2BSD version.
   Copyright (C) 1996, 1997 Free Software Foundation, Inc.
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

#ifndef _DIRENT_H
# error "Never use <bits/dirent.h> directly; include <dirent.h> instead."
#endif

struct dirent
  {
    unsigned int d_fileno;	/* 32 bits.  */
    unsigned short int d_reclen; /* 16 bits.  */
    unsigned short int d_namlen; /* 16 bits.  */
    char d_name[1];		/* Variable length.  */
  };

#define _DIRENT_HAVE_D_RECLEN 1
#define _DIRENT_HAVE_D_NAMLEN 1
