/* Copyright (C) 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Written by Ulrich Drepper, <drepper@cygnus.com>.

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

/* Find index of weight.  */
static inline int32_t
findidx (const unsigned char **cpp)
{
  int_fast32_t i = table[*(*cpp)++];
  const unsigned char *cp;

  if (i >= 0)
    /* This is an index into the weight table.  Cool.  */
    return i;

  /* Oh well, more than one sequence starting with this byte.
     Search for the correct one.  */
  cp = &extra[-i];
  while (1)
    {
      size_t nhere;
      const unsigned char *usrc = *cpp;

      /* The first thing is the index.  */
      i = *((int32_t *) cp);
      cp += sizeof (int32_t);

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

	  for (cnt = 0; cnt < nhere; ++cnt)
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
	  size_t offset = 0;

	  for (cnt = 0; cnt < nhere; ++cnt)
	    if (cp[cnt] != usrc[cnt])
	      break;

	  if (cnt != nhere)
	    {
	      if (cp[cnt] > usrc[cnt])
		{
		  /* Cannot be in this range.  */
		  cp += 2 * nhere;
		  continue;
		}

	      /* Test against the end of the range.  */
	      for (cnt = 0; cnt < nhere; ++cnt)
		if (cp[nhere + cnt] != usrc[cnt])
		  break;

	      if (cnt != nhere && cp[nhere + cnt] < usrc[cnt])
		{
		  /* Cannot be in this range.  */
		  cp += 2 * nhere;
		  continue;
		}

	      /* This range matches the next characters.  Now find
		 the offset in the indirect table.  */
	      for (cnt = 0; cp[cnt] == usrc[cnt]; ++cnt);

	      do
		{
		  offset <<= 8;
		  offset += usrc[cnt] - cp[cnt];
		}
	      while (++cnt < nhere);
	    }

	  *cpp += nhere;
	  return offset;
	}
    }

  /* NOTREACHED */
  return 0x43219876;
}
