/* Internal header containing implementation of wcwidth() function.
   Copyright (C) 1996, 1997, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1996.

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

#include <wchar.h>
#include <wctype.h>
#include "../wctype/wchar-lookup.h"

/* Table containing width information.  */
extern const char *__ctype32_width;

static __inline int
internal_wcwidth (wint_t wc)
{
  unsigned char res;

  /* The tables have been prepared in such a way that
     1. wc == L'\0' yields res = 0,
     2. !iswprint (wc) implies res = '\xff'.  */
  res = wcwidth_table_lookup (__ctype32_width, wc);

  return res == (unsigned char) '\xff' ? -1 : (int) res;
}
