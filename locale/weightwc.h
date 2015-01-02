/* Copyright (C) 1996-2015 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Ulrich Drepper, <drepper@cygnus.com>.

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

#ifndef _WEIGHTWC_H_
#define _WEIGHTWC_H_	1

/* Find index of weight.  */
static inline int32_t __attribute__ ((always_inline))
findidx (const int32_t *table,
	 const int32_t *indirect,
	 const wint_t *extra,
	 const wint_t **cpp, size_t len)
{
  wint_t ch = *(*cpp)++;
  int32_t i = __collidx_table_lookup ((const char *) table, ch);

  if (i >= 0)
    /* This is an index into the weight table.  Cool.  */
    return i;

  /* Oh well, more than one sequence starting with this byte.
     Search for the correct one.  */
  const int32_t *cp = (const int32_t *) &extra[-i];
  --len;
  while (1)
    {
      size_t nhere;
      const int32_t *usrc = (const int32_t *) *cpp;

      /* The first thing is the index.  */
      i = *cp++;

      /* Next is the length of the byte sequence.  These are always
	 short byte sequences so there is no reason to call any
	 function (even if they are inlined).  */
      nhere = *cp++;

      if (i >= 0)
	{
	  /* It is a single character.  If it matches we found our
	     index.  Note that at the end of each list there is an
	     entry of length zero which represents the single byte
	     sequence.  The first (and here only) byte was tested
	     already.  */
	  size_t cnt;

	  for (cnt = 0; cnt < nhere && cnt < len; ++cnt)
	    if (cp[cnt] != usrc[cnt])
	      break;

	  if (cnt == nhere)
	    {
	      /* Found it.  */
	      *cpp += nhere;
	      return i;
	    }

	  /* Up to the next entry.  */
	  cp += nhere;
	}
      else
	{
	  /* This is a range of characters.  First decide whether the
	     current byte sequence lies in the range.  */
	  size_t cnt;
	  size_t offset;

	  for (cnt = 0; cnt < nhere - 1 && cnt < len; ++cnt)
	    if (cp[cnt] != usrc[cnt])
	      break;

	  if (cnt < nhere - 1)
	    {
	      cp += 2 * nhere;
	      continue;
	    }

	  if (cp[nhere - 1] > usrc[nhere -1])
	    {
	      cp += 2 * nhere;
	      continue;
	    }

	  if (cp[2 * nhere - 1] < usrc[nhere -1])
	    {
	      cp += 2 * nhere;
	      continue;
	    }

	  /* This range matches the next characters.  Now find
	     the offset in the indirect table.  */
	  offset = usrc[nhere - 1] - cp[nhere - 1];
	  *cpp += nhere;

	  return indirect[-i + offset];
	}
    }

  /* NOTREACHED */
  return 0x43219876;
}

#endif	/* weightwc.h */
