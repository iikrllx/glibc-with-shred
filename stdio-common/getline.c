/* Copyright (C) 1991-2013 Free Software Foundation, Inc.
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

#include <stddef.h>
#include <stdio.h>

#undef __getline

#include "../libio/libioP.h"
#undef ssize_t
#define ssize_t _IO_ssize_t
#define __getdelim _IO_getdelim

/* Like getdelim, but always looks for a newline.  */
ssize_t
__getline (char **lineptr, size_t *n, FILE *stream)
{
  return __getdelim (lineptr, n, '\n', stream);
}

weak_alias (__getline, getline)
