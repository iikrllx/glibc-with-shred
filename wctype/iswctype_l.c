/* Copyright (C) 1996, 1997, 2000 Free Software Foundation, Inc.
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

#include <ctype.h>
#include <wctype.h>

#define USE_IN_EXTENDED_LOCALE_MODEL	1
#include "cname-lookup.h"
#include "wchar-lookup.h"


int
__iswctype_l (wint_t wc, wctype_t desc, __locale_t locale)
{
  if (locale->__locales[LC_CTYPE]->values[_NL_ITEM_INDEX (_NL_CTYPE_HASH_SIZE)].word != 0)
    {
      /* Old locale format.  */
      const uint32_t *class32_b;
      size_t idx;

      idx = cname_lookup (wc, locale);
      if (idx == ~((size_t) 0))
	return 0;

      class32_b = (uint32_t *)
	locale->__locales[LC_CTYPE]->values[_NL_ITEM_INDEX (_NL_CTYPE_CLASS32)].string;

      return class32_b[idx] & desc;
    }
  else
    {
      /* If the user passes in an invalid DESC valid (the one returned from
	 `__wctype_l' in case of an error) simply return 0.  */
      if (desc == (wctype_t) 0)
	return 0;

      /* New locale format.  */
      return wctype_table_lookup ((const char *) desc, wc);
    }
}
