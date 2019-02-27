/* Copyright (C) 1995-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.

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

#include <wchar.h>


#ifdef WCSCPY
# define __wcscpy WCSCPY
#endif

/* Copy SRC to DEST.  */
wchar_t *
__wcscpy (wchar_t *dest, const wchar_t *src)
{
  return __wmemcpy (dest, src, __wcslen (src) + 1);
}
#ifndef WCSCPY
weak_alias (__wcscpy, wcscpy)
libc_hidden_def (__wcscpy)
#endif
