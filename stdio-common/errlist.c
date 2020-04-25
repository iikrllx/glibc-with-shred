/* Copyright (C) 1991-2020 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <stdio.h>
#include <errno.h>
#include <libintl.h>
#include <array_length.h>

const char *const _sys_errlist_internal[] =
  {
#define _S(n, str)         [n] = str,
#include <errlist.h>
#undef _S
  };

const char *
__get_errlist (int errnum)
{
  if (errnum >= 0 && errnum < array_length (_sys_errlist_internal))
    return _sys_errlist_internal[errnum];
  return NULL;
}

#include <errlist-compat.c>
