/* Mapping tables for EUC-CN handling.
   Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#include <gb2312.h>
#include <stdint.h>

/* Definitions used in the body of the `gconv' function.  */
#define CHARSET_NAME		"EUC-CN//"
#define FROM_LOOP		from_euc_cn
#define TO_LOOP			to_euc_cn
#define DEFINE_INIT		1
#define DEFINE_FINI		1
#define MIN_NEEDED_FROM		1
#define MAX_NEEDED_FROM		2
#define MIN_NEEDED_TO		4


/* First define the conversion function from EUC-CN to UCS4.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_INPUT	MAX_NEEDED_FROM
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_TO
#define LOOPFCT			FROM_LOOP
#define BODY \
  {									      \
    uint32_t ch = *inptr;						      \
									      \
    if (ch <= 0x7f)							      \
      ++inptr;								      \
    else								      \
      if ((__builtin_expect (ch, 0xa1) <= 0xa0 && ch != 0x8e && ch != 0x8f)   \
	  || __builtin_expect (ch, 0xfe) > 0xfe)			      \
	{								      \
	  /* This is illegal.  */					      \
	  if (! ignore_errors_p ())					      \
	    {								      \
	      result = __GCONV_ILLEGAL_INPUT;				      \
	      break;							      \
	    }								      \
									      \
	  ++inptr;							      \
	  ++*irreversible;						      \
	  continue;							      \
	}								      \
      else								      \
	{								      \
	  /* Two or more byte character.  First test whether the	      \
	     next character is also available.  */			      \
	  const unsigned char *endp;					      \
									      \
	  if (NEED_LENGTH_TEST && __builtin_expect (inptr + 1 >= inend, 0))   \
	    {								      \
	      /* The second character is not available.  Store		      \
		 the intermediate result.  */				      \
	      result = __GCONV_INCOMPLETE_INPUT;			      \
	      break;							      \
	    }								      \
									      \
	  ch = inptr[1];						      \
									      \
	  /* All second bytes of a multibyte character must be >= 0xa1. */    \
	  if (__builtin_expect (ch, 0xa1) < 0xa1)			      \
	    {								      \
	      if (! ignore_errors_p ())					      \
		{							      \
		  /* This is an illegal character.  */			      \
		  result = __GCONV_ILLEGAL_INPUT;			      \
		  break;						      \
		}							      \
									      \
	      ++inptr;							      \
	      ++*irreversible;						      \
	      continue;							      \
	    }								      \
									      \
	  /* This is code set 1: GB 2312-80.  */			      \
	  endp = inptr;							      \
									      \
	  ch = gb2312_to_ucs4 (&endp, 2, 0x80);				      \
	  if (__builtin_expect (ch, 0) == __UNKNOWN_10646_CHAR)		      \
	    {								      \
	      /* This is an illegal character.  */			      \
	      if (! ignore_errors_p ())					      \
		{							      \
		  /* This is an illegal character.  */			      \
		  result = __GCONV_ILLEGAL_INPUT;			      \
		  break;						      \
		}							      \
									      \
	      inptr += 2;						      \
	      ++*irreversible;						      \
	      continue;							      \
	    }								      \
									      \
	  inptr += 2;							      \
	}								      \
									      \
    put32 (outptr, ch);							      \
    outptr += 4;							      \
  }
#include <iconv/loop.c>


/* Next, define the other direction.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_TO
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_OUTPUT	MAX_NEEDED_FROM
#define LOOPFCT			TO_LOOP
#define BODY \
  {									      \
    uint32_t ch = get32 (inptr);					      \
									      \
    if (ch <= L'\x7f')							      \
      /* It's plain ASCII.  */						      \
      *outptr++ = (unsigned char) ch;					      \
    else								      \
      {									      \
	size_t found;							      \
									      \
	found = ucs4_to_gb2312 (ch, outptr,				      \
				(NEED_LENGTH_TEST			      \
				 ? outend - outptr : MAX_NEEDED_OUTPUT));     \
	if (!NEED_LENGTH_TEST || __builtin_expect (found, 1) != 0)	      \
	  {								      \
	    if (__builtin_expect (found, 0) == __UNKNOWN_10646_CHAR)	      \
	      {								      \
		/* Illegal character.  */				      \
		if (! ignore_errors_p ())				      \
		  {							      \
		    result = __GCONV_ILLEGAL_INPUT;			      \
		    break;						      \
		  }							      \
									      \
		inptr += 4;						      \
		++*irreversible;					      \
		continue;						      \
	      }								      \
									      \
	    /* It's a GB 2312 character, adjust it for EUC-CN.  */	      \
	    *outptr++ += 0x80;						      \
	    *outptr++ += 0x80;						      \
	  }								      \
	else								      \
	  {								      \
	    /* We ran out of space.  */					      \
	    result = __GCONV_FULL_OUTPUT;				      \
	    break;							      \
	  }								      \
      }									      \
    inptr += 4;								      \
  }
#include <iconv/loop.c>


/* Now define the toplevel functions.  */
#include <iconv/skeleton.c>
