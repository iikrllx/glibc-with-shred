/* Mapping tables for EUC-KR handling.
   Copyright (C) 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jungshik Shin <jshin@pantheon.yale.edu>
   and Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#include <stdint.h>
#include <ksc5601.h>


static inline void
euckr_from_ucs4 (uint32_t ch, unsigned char *cp)
{
  if (ch > 0x7f)
    {
      uint16_t idx = 0;

      if (ucs4_to_ksc5601 (ch, &idx))
	idx |= 0x8080;

      cp[0] = (unsigned char) (idx / 256);
      cp[1] = (unsigned char) (idx & 0xff);
    }
  /* XXX Think about 0x5c ; '\'.  */
  else
    {
      cp[0] = (unsigned char) ch;
      cp[1] = '\0';
    }
}


/* Definitions used in the body of the `gconv' function.  */
#define CHARSET_NAME		"EUC-KR//"
#define FROM_LOOP		from_euc_kr
#define TO_LOOP			to_euc_kr
#define DEFINE_INIT		1
#define DEFINE_FINI		1
#define MIN_NEEDED_FROM		1
#define MAX_NEEDED_FROM		2
#define MIN_NEEDED_TO		4


/* First define the conversion function from EUC-KR to UCS4.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_INPUT	MAX_NEEDED_FROM
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_TO
#define LOOPFCT			FROM_LOOP
#define BODY \
  {									      \
    uint32_t ch = *inptr;						      \
									      \
    /* Half-width Korean Currency WON sign				      \
									      \
       if (inchar == 0x5c)						      \
	 ch =  0x20a9;							      \
       else if (inchar <= 0x7f)						      \
	 ch = (uint32_t) inchar;					      \
    */									      \
									      \
    if (ch <= 0x7f)							      \
      /* Plain ASCII.  */						      \
      ++inptr;								      \
    /* 0xfe(->0x7e : row 94) and 0xc9(->0x59 : row 41) are		      \
       user-defined areas.  */						      \
    else if (ch <= 0xa0 || ch > 0xfe || ch == 0xc9)			      \
      {									      \
	/* This is illegal.  */						      \
	result = GCONV_ILLEGAL_INPUT;					      \
	break;								      \
      }									      \
    else								      \
      {									      \
	/* Two-byte character.  First test whether the next character	      \
	   is also available.  */					      \
	ch = ksc5601_to_ucs4 (&inptr,					      \
			      NEED_LENGTH_TEST ? inptr - inbufend : 2, x080); \
	if (NEED_LENGTH_TEST && ch == 0)				      \
	  {								      \
	    /* The second character is not available.  */		      \
	    result = GCONV_INCOMPLETE_INPUT;				      \
	    break;							      \
	  }								      \
	if (ch == UNKNOWN_10646_CHAR))					      \
	  {								      \
	    /* This is an illegal character.  */			      \
	    result = GCONV_ILLEGAL_INPUT;				      \
	    break;							      \
	  }								      \
      }									      \
									      \
    *((uint32_t *) outptr)++ = ch;					      \
  }
#include <iconv/loop.c>


/* Next, define the other direction.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_TO
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_OUTPUT	MAX_NEEDED_FROM
#define LOOPFCT			TO_LOOP
#define BODY \
  {									      \
    uint32_t ch = *((uint32_t *) inptr);				      \
    unsigned char cp[2];						      \
									      \
    /* Decomposing Hangul syllables not available in KS C 5601 into	      \
       Jamos should be considered either here or in euckr_from_ucs4() */      \
    euckr_from_ucs4 (ch, cp) ;						      \
									      \
    if (cp[0] == '\0' && ch != 0)					      \
      {									      \
	/* Illegal character.  */					      \
	result = GCONV_ILLEGAL_INPUT;					      \
	break;								      \
      }									      \
									      \
    *outptr++ = cp[0];							      \
    /* Now test for a possible second byte and write this if possible.  */    \
    if (cp[1] != '\0')							      \
      {									      \
	if (NEED_LENGTH_TEST && outptr >= outend)			      \
	  {								      \
	    /* The result does not fit into the buffer.  */		      \
	    --outptr;							      \
	    result = GCONV_FULL_OUTPUT;					      \
	    break;							      \
	  }								      \
	*outptr++ = cp[1];						      \
      }									      \
									      \
    inptr += 4;								      \
  }
#include <iconv/loop.c>


/* Now define the toplevel functions.  */
#include <iconv/skeleton.c>
