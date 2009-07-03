/* strcspn with SSE4.2 intrinsics
   Copyright (C) 2009 Free Software Foundation, Inc.
   Contributed by Intel Corporation.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <nmmintrin.h>
#include <string.h>

/* We use 0x2:
	_SIDD_SBYTE_OPS
	| _SIDD_CMP_EQUAL_ANY
	| _SIDD_POSITIVE_POLARITY
	| _SIDD_LEAST_SIGNIFICANT
   on pcmpistri to compare xmm/mem128

   0 1 2 3 4 5 6 7 8 9 A B C D E F
   X X X X X X X X X X X X X X X X

   against xmm

   0 1 2 3 4 5 6 7 8 9 A B C D E F
   A A A A A A A A A A A A A A A A

   to find out if the first 16byte data element has any byte A and
   the offset of the first byte.  There are 3 cases:

   1. The first 16byte data element has the byte A at the offset X.
   2. The first 16byte data element has EOS and doesn't have the byte A.
   3. The first 16byte data element is valid and doesn't have the byte A.

   Here is the table of ECX, CFlag, ZFlag and SFlag for 2 cases:

    1		 X	  1	 0/1	  0
    2		16	  0	  1	  0
    3		16	  0	  0	  0

   We exit from the loop for cases 1 and 2 with jbe which branches
   when either CFlag or ZFlag is 1.  If CFlag == 1, ECX has the offset
   X for case 1.  */

#ifndef STRCSPN_SSE2
#define STRCSPN_SSE2 __strcspn_sse2
#define STRCSPN_SSE42 __strcspn_sse42
#endif

extern
#ifdef USE_AS_STRPBRK
char *
#else
size_t
#endif
STRCSPN_SSE2 (const char *, const char *);

#ifdef USE_AS_STRPBRK
char *
#else
size_t
#endif
__attribute__ ((section (".text.sse4.2")))
STRCSPN_SSE42 (const char *s, const char *a)
{
  int offset;
  const char *aligned;
  __m128i mask, mask0, mask1;
  __m128i value;
  int index, length;
  int cflag, zflag;

  if (*a == 0)
#ifdef USE_AS_STRPBRK
    return NULL;
#else
    return strlen (s);
#endif

  offset = (int) ((size_t) a & 15);
  if (offset != 0)
    {
      /* Load masks.  */
      aligned = (const char *) ((size_t) a & 0xfffffffffffffff0L);
      mask0 = _mm_load_si128 ((__m128i *) aligned);

      switch (offset)
	{
	case 1:
	  mask = _mm_srli_si128 (mask0, 1);
	  break;
	case 2:
	  mask = _mm_srli_si128 (mask0, 2);
	  break;
	case 3:
	  mask = _mm_srli_si128 (mask0, 3);
	  break;
	case 4:
	  mask = _mm_srli_si128 (mask0, 4);
	  break;
	case 5:
	  mask = _mm_srli_si128 (mask0, 5);
	  break;
	case 6:
	  mask = _mm_srli_si128 (mask0, 6);
	  break;
	case 7:
	  mask = _mm_srli_si128 (mask0, 7);
	  break;
	case 8:
	  mask = _mm_srli_si128 (mask0, 8);
	  break;
	case 9:
	  mask = _mm_srli_si128 (mask0, 9);
	  break;
	case 10:
	  mask = _mm_srli_si128 (mask0, 10);
	  break;
	case 11:
	  mask = _mm_srli_si128 (mask0, 11);
	  break;
	case 12:
	  mask = _mm_srli_si128 (mask0, 12);
	  break;
	case 13:
	  mask = _mm_srli_si128 (mask0, 13);
	  break;
	case 14:
	  mask = _mm_srli_si128 (mask0, 14);
	  break;
	case 15:
	  mask = _mm_srli_si128 (mask0, 15);
	  break;
	}

      /* Find where the NULL terminator is.  */
      length = _mm_cmpistri (mask, mask, 0x3a);
      if (length == 16 - offset)
	{
	  /* There is no NULL terminator.  */
	  mask1 = _mm_load_si128 ((__m128i *) (aligned + 16));
	  index = _mm_cmpistri (mask1, mask1, 0x3a);
	  length += index;

	  /* Don't use SSE4.2 if the length of A > 16.  */
	  if (length > 16)
	    return STRCSPN_SSE2 (s, a);

	  if (index != 0)
	    {
	      /* Combine mask0 and mask1.  */
	      switch (offset)
		{
		case 1:
		  mask = _mm_alignr_epi8 (mask1, mask0, 1);
		  break;
		case 2:
		  mask = _mm_alignr_epi8 (mask1, mask0, 2);
		  break;
		case 3:
		  mask = _mm_alignr_epi8 (mask1, mask0, 3);
		  break;
		case 4:
		  mask = _mm_alignr_epi8 (mask1, mask0, 4);
		  break;
		case 5:
		  mask = _mm_alignr_epi8 (mask1, mask0, 5);
		  break;
		case 6:
		  mask = _mm_alignr_epi8 (mask1, mask0, 6);
		  break;
		case 7:
		  mask = _mm_alignr_epi8 (mask1, mask0, 7);
		  break;
		case 8:
		  mask = _mm_alignr_epi8 (mask1, mask0, 8);
		  break;
		case 9:
		  mask = _mm_alignr_epi8 (mask1, mask0, 9);
		  break;
		case 10:
		  mask = _mm_alignr_epi8 (mask1, mask0, 10);
		  break;
		case 11:
		  mask = _mm_alignr_epi8 (mask1, mask0, 11);
		  break;
		case 12:
		  mask = _mm_alignr_epi8 (mask1, mask0, 12);
		  break;
		case 13:
		  mask = _mm_alignr_epi8 (mask1, mask0, 13);
		  break;
		case 14:
		  mask = _mm_alignr_epi8 (mask1, mask0, 14);
		  break;
		case 15:
		  mask = _mm_alignr_epi8 (mask1, mask0, 15);
		  break;
		}
	    }
	}
    }
  else
    {
      /* A is aligned.  */
      mask = _mm_load_si128 ((__m128i *) a);

      /* Find where the NULL terminator is.  */
      length = _mm_cmpistri (mask, mask, 0x3a);
      if (length == 16)
	{
	  /* There is no NULL terminator.  Don't use SSE4.2 if the length
	     of A > 16.  */
	  if (a[16] != 0)
	    return STRCSPN_SSE2 (s, a);
	}
    }

  offset = (int) ((size_t) s & 15);
  if (offset != 0)
    {
      /* Check partial string.  */
      aligned = (const char *) ((size_t) s & 0xfffffffffffffff0L);
      value = _mm_load_si128 ((__m128i *) aligned);

      switch (offset)
	{
	case 1:
	  value = _mm_srli_si128 (value, 1);
	  break;
	case 2:
	  value = _mm_srli_si128 (value, 2);
	  break;
	case 3:
	  value = _mm_srli_si128 (value, 3);
	  break;
	case 4:
	  value = _mm_srli_si128 (value, 4);
	  break;
	case 5:
	  value = _mm_srli_si128 (value, 5);
	  break;
	case 6:
	  value = _mm_srli_si128 (value, 6);
	  break;
	case 7:
	  value = _mm_srli_si128 (value, 7);
	  break;
	case 8:
	  value = _mm_srli_si128 (value, 8);
	  break;
	case 9:
	  value = _mm_srli_si128 (value, 9);
	  break;
	case 10:
	  value = _mm_srli_si128 (value, 10);
	  break;
	case 11:
	  value = _mm_srli_si128 (value, 11);
	  break;
	case 12:
	  value = _mm_srli_si128 (value, 12);
	  break;
	case 13:
	  value = _mm_srli_si128 (value, 13);
	  break;
	case 14:
	  value = _mm_srli_si128 (value, 14);
	  break;
	case 15:
	  value = _mm_srli_si128 (value, 15);
	  break;
	}

      length = _mm_cmpistri (mask, value, 0x2);
      /* No need to check ZFlag since ZFlag is always 1.  */
      cflag = _mm_cmpistrc (mask, value, 0x2);
      if (cflag)
#ifdef USE_AS_STRPBRK
	return (char *) (s + length);
#else
	return length;
#endif
      /* Find where the NULL terminator is.  */
      index = _mm_cmpistri (value, value, 0x3a);
      if (index < 16 - offset)
#ifdef USE_AS_STRPBRK
	return NULL;
#else
	return index;
#endif
      aligned += 16;
    }
  else
    aligned = s;

loop:
  value = _mm_load_si128 ((__m128i *) aligned);
  index = _mm_cmpistri (mask, value, 0x2);
  cflag = _mm_cmpistrc (mask, value, 0x2);
  zflag = _mm_cmpistrz (mask, value, 0x2);
  if (cflag)
#ifdef USE_AS_STRPBRK
    return (char *) (aligned + index);
#else
    return (size_t) (aligned + index - s);
#endif
  if (zflag)
#ifdef USE_AS_STRPBRK
    return NULL;
#else
    {
      /* Find where the NULL terminator is.  */
      index = _mm_cmpistri (value, value, 0x3a);
      return (size_t) (aligned + index - s);
    }
#endif
  aligned += 16;
  goto loop;
}
