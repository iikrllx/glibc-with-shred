/* Copyright (C) 1998-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#ifdef WCSNLEN
# define __wcsnlen WCSNLEN
#endif

/* Return length of string S at most maxlen.  */
size_t
__wcsnlen (const wchar_t *s, size_t maxlen)
{
  size_t len = 0;

  while (maxlen > 0 && s[len] != L'\0')
    {
      ++len;
      if (--maxlen == 0 || s[len] == L'\0')
	return len;
      ++len;
      if (--maxlen == 0 || s[len] == L'\0')
	return len;
      ++len;
      if (--maxlen == 0 || s[len] == L'\0')
	return len;
      ++len;
      --maxlen;
    }

  return len;
}
#ifndef WCSNLEN
weak_alias (__wcsnlen, wcsnlen)
#endif
