/* Conversion module for ISO-2022-KR.
   Copyright (C) 1998 Free Software Foundation, Inc.
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

#include <gconv.h>
#include <stdint.h>
#include <string.h>
#include "ksc5601.h"

#include <assert.h>

/* This makes obvious what everybody knows: 0x1b is the Esc character.  */
#define ESC	0x1b

/* The shift sequences for this charset (it does not use ESC).  */
#define SI	0x0f
#define SO	0x0e

/* Definitions used in the body of the `gconv' function.  */
#define CHARSET_NAME		"ISO-2022-KR//"
#define DEFINE_INIT		1
#define DEFINE_FINI		1
#define FROM_LOOP		from_iso2022kr_loop
#define TO_LOOP			to_iso2022kr_loop
#define MIN_NEEDED_FROM		1
#define MAX_NEEDED_FROM		3
#define MIN_NEEDED_TO		4
#define MAX_NEEDED_TO		4
#define PREPARE_LOOP \
  int save_set;								      \
  int *setp = &data->statep->count;					      \
  if (!FROM_DIRECTION && !data->internal_use && data->invocation_counter == 0)\
    {									      \
      /* Emit the designator sequence.  */				      \
      if (outbuf + 4 > outend)						      \
	return GCONV_FULL_OUTPUT;					      \
									      \
      *outbuf++ = ESC;							      \
      *outbuf++ = '$';							      \
      *outbuf++ = ')';							      \
      *outbuf++ = 'C';							      \
    }
#define EXTRA_LOOP_ARGS		, setp


/* The COUNT element of the state keeps track of the currently selected
   character set.  The possible values are:  */
enum
{
  ASCII_set = 0,
  KSC5601_set
};


/* Since this is a stateful encoding we have to provide code which resets
   the output state to the initial state.  This has to be done during the
   flushing.  */
#define EMIT_SHIFT_TO_INIT \
  if (data->statep->count != ASCII_set)					      \
    {									      \
      if (FROM_DIRECTION)						      \
	/* It's easy, we don't have to emit anything, we just reset the	      \
	   state for the input.  */					      \
	data->statep->count = ASCII_set;				      \
      else								      \
	{								      \
	  char *outbuf = data->outbuf;					      \
	  								      \
	  /* We are not in the initial state.  To switch back we have	      \
	     to emit `SI'.  */						      \
	  if (outbuf == data->outbufend)				      \
	    /* We don't have enough room in the output buffer.  */	      \
	    status = GCONV_FULL_OUTPUT;					      \
	  else								      \
	    {								      \
	      /* Write out the shift sequence.  */			      \
	      *outbuf++ = SI;						      \
	      data->outbuf = outbuf;					      \
	      data->statep->count = ASCII_set;				      \
	    }								      \
	}								      \
    }


/* Since we might have to reset input pointer we must be able to save
   and retore the state.  */
#define SAVE_RESET_STATE(Save) \
  if (Save)								      \
    save_set = *setp;							      \
  else									      \
    *setp = save_set


/* First define the conversion function from ISO-2022-JP to UCS4.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_INPUT	MAX_NEEDED_FROM
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_TO
#define LOOPFCT			FROM_LOOP
#define BODY \
  {									      \
    uint32_t ch = *inptr;						      \
									      \
    /* This is a 7bit character set, disallow all 8bit characters.  */	      \
    if (ch > 0x7f)							      \
      {									      \
	result = GCONV_ILLEGAL_INPUT;					      \
	break;								      \
      }									      \
									      \
    /* Recognize escape sequences.  */					      \
    if (ch == ESC)							      \
      {									      \
	/* We don't really have to handle escape sequences since all the      \
	   switching is done using the SI and SO bytes.  But we have to	      \
	   recognize `Esc $ ) C' since this is a kind of flag for this	      \
	   encoding.  We simply ignore it.  */				      \
	if (inptr + 1 > inend						      \
	    || (inptr[1] == '$'						      \
		&& (inptr + 2 > inend					      \
		    || (inptr[2] == ')' && inptr + 3 > inend))))	      \
									      \
	  {								      \
	    result = GCONV_EMPTY_INPUT;					      \
	    break;							      \
	  }								      \
	if (inptr[1] == '$' && inptr[2] == ')' && inptr[3] == 'C')	      \
	  {								      \
	    /* Yeah, yeah, we know this is ISO 2022-KR.  */		      \
	    inptr += 4;							      \
	    continue;							      \
	  }								      \
      }									      \
    else if (ch == SO)							      \
      {									      \
	/* Switch to use KSC.  */					      \
	++inptr;							      \
	set = KSC5601_set;						      \
	continue;							      \
      }									      \
    else if (ch == SI)							      \
      {									      \
	/* Switch to use ASCII.  */					      \
	++inptr;							      \
	set = ASCII_set;						      \
	continue;							      \
      }									      \
									      \
    if (set == ASCII_set)						      \
      {									      \
	if (ch >= 0x80)							      \
	  {								      \
	    result = GCONV_ILLEGAL_INPUT;				      \
	    break;							      \
	  }								      \
	/* Almost done, just advance the input pointer.  */		      \
	++inptr;							      \
      }									      \
    else								      \
      {									      \
	assert (set == KSC5601_set);					      \
									      \
	/* Use the KSC 5601 table.  */					      \
	ch = ksc5601_to_ucs4 (&inptr,					      \
			      NEED_LENGTH_TEST ? inend - inptr : 2, 0);	      \
									      \
	if (NEED_LENGTH_TEST && ch == 0)				      \
	  {								      \
	    result = GCONV_EMPTY_INPUT;					      \
	    break;							      \
	  }								      \
	else if (ch == UNKNOWN_10646_CHAR)				      \
	  {								      \
	    result = GCONV_ILLEGAL_INPUT;				      \
	    break;							      \
	  }								      \
      }									      \
									      \
    *((uint32_t *) outptr)++ = ch;					      \
  }
#define EXTRA_LOOP_DECLS	, int *setp
#define INIT_PARAMS		int set = *setp
#define UPDATE_PARAMS		*setp = set
#include <iconv/loop.c>


/* Next, define the other direction.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_TO
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_OUTPUT	MAX_NEEDED_FROM
#define LOOPFCT			TO_LOOP
#define BODY \
  {									      \
    uint32_t ch;							      \
    size_t written = 0;							      \
									      \
    ch = *((uint32_t *) inptr);						      \
									      \
    /* First see whether we can write the character using the currently	      \
       selected character set.  */					      \
    if (ch < 0x80)							      \
      {									      \
	if (set != ASCII_set)						      \
	  {								      \
	    *outptr++ = SI;						      \
	    set = ASCII_set;						      \
	    if (NEED_LENGTH_TEST && outptr == outend)			      \
	      {								      \
		result = GCONV_FULL_OUTPUT;				      \
		break;							      \
	      }								      \
	  }								      \
 									      \
	*outptr++ = ch;							      \
	written = 1;							      \
      }									      \
    else								      \
      {									      \
	char buf[2];							      \
									      \
	written = ucs4_to_ksc5601 (ch, buf, 2);				      \
									      \
	if (written == UNKNOWN_10646_CHAR)				      \
	  {								      \
	    /* Illegal character.  */					      \
	    result = GCONV_ILLEGAL_INPUT;				      \
	    break;							      \
	  }								      \
	assert (written == 2);						      \
									      \
	/* We use KSC 5601.  */						      \
	if (set != KSC5601_set)						      \
	  {								      \
	    *outptr++ = SO;						      \
	    set = KSC5601_set;						      \
	  }								      \
									      \
	if (NEED_LENGTH_TEST && outptr + 2 > outend)			      \
	  {								      \
	    result = GCONV_FULL_OUTPUT;					      \
	    break;							      \
	  }								      \
									      \
	*outptr++ = buf[0];						      \
	*outptr++ = buf[1];						      \
      }									      \
									      \
    /* Now that we wrote the output increment the input pointer.  */	      \
    inptr += 4;								      \
  }
#define EXTRA_LOOP_DECLS	, int *setp
#define INIT_PARAMS		int set = *setp
#define UPDATE_PARAMS		*setp = set
#include <iconv/loop.c>


/* Now define the toplevel functions.  */
#include <iconv/skeleton.c>
