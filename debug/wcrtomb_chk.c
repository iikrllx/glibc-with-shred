/* Copyright (C) 2005-2017 Free Software Foundation, Inc.
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

#include <langinfo.h>
#include <locale.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale/localeinfo.h>


size_t
__wcrtomb_chk (char *s, wchar_t wchar, mbstate_t *ps, size_t buflen)
{
  /* We do not have to implement the full wctomb semantics since we
     know that S cannot be NULL when we come here.  */
  if (buflen < MB_CUR_MAX)
    __chk_fail ();

  return __wcrtomb (s, wchar, ps);
}
