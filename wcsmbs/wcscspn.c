/* Copyright (C) 1995, 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by Ulrich Drepper, <drepper@gnu.ai.mit.edu>

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.	 If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <wchar.h>


/* Return the length of the maximum initial segment
   of WCS which contains only wide-characters not in REJECT.  */
size_t
wcscspn (wcs, reject)
     const wchar_t *wcs;
     const wchar_t *reject;
{
  register size_t count = 0;

  while (*wcs != L'\0')
    if (wcschr (reject, *wcs++) == NULL)
      ++count;
    else
      return count;

  return count;
}
