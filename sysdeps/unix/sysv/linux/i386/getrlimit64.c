/* Copyright (C) 1999 Free Software Foundation, Inc.
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

#define getrlimit64 __new_getrlimit64

#include <sysdeps/generic/getrlimit64.c>

#undef getrlimit64
#if defined PIC && defined DO_VERSIONING
default_symbol_version (__new_getrlimit64, getrlimit64, GLIBC_2.2);
#else
weak_alias (__new_getrlimit64, getrlimit64);
#endif
