/* Access functions for JISX0201 conversion.
   Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#ifndef _JIS0201_H
#define _JIS0201_H	1

/* Conversion table.  */
extern const wchar_t jis0201_to_ucs4[];


static inline wchar_t
jisx0201_to_ucs4 (char **s, size_t avail __attribute__ ((unused)))
{
  wchar_t val = jis0201_to_ucs4[*(unsigned char *) (*s)];

  if (val == 0 && **s != '\0')
    val = UNKNOWN_10646_CHAR;

  return val;
}


static inline size_t
ucs4_to_jisx0201 (wchar_t wch, char **s, size_t avail __attribute__ ((unused)))
{
  char ch;

  if (wch == 0xa5)
    ch = '\x5c';
  else if (wch == 0x203e)
    ch = '\x7e';
  else if (wch < 0x7e)
    ch = wch;
  else if (wch >= 0xff61 && wch <= 0xff9f)
    ch = wch - 0xfec0;
  else
    return 0;

  *(*s)++ = ch;
  return 1;
}

#endif /* jis0201.h */
