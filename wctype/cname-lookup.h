/* Copyright (C) 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by Ulrich Drepper, <drepper@gnu.ai.mit.edu>.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include "../locale/localeinfo.h"

/* Some words on the runtime of this functions.  Although there is a
   loop in the function the runtime is asymptotically quasi constant.
   The reason is that even for the largest character sets HASH_LAYERS
   will not grow beyond 15 (a guess!).  */
static __inline size_t
cname_lookup (wint_t wc)
{
  extern unsigned int *__ctype_names;
  unsigned int hash_size, hash_layers;
  size_t result, cnt;

  hash_size = _NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_HASH_SIZE);
  hash_layers = _NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_HASH_LAYERS);

  result = wc % hash_size;
  for (cnt = 0; cnt < hash_layers; ++cnt)
    {
      if (__ctype_names[result] == wc)
	break;
      result += hash_size;
    }

  return cnt < hash_layers ? result : ~((size_t) 0);
}
