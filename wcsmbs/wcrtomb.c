/* Copyright (C) 1996, 1997, 1998, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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

#include <errno.h>
#include <gconv.h>
#include <stdlib.h>
#include <wchar.h>
#include <wcsmbsload.h>

#include <assert.h>

#ifndef EILSEQ
# define EILSEQ EINVAL
#endif


/* This is the private state used if PS is NULL.  */
static mbstate_t state;

size_t
__wcrtomb (char *s, wchar_t wc, mbstate_t *ps)
{
  mbstate_t temp_state;
  char buf[MB_CUR_MAX];
  struct __gconv_step_data data;
  int status;
  size_t result;
  size_t dummy;

  /* Set information for this step.  */
  data.__invocation_counter = 0;
  data.__internal_use = 1;
  data.__flags = __GCONV_IS_LAST;
  data.__statep = ps ?: &state;

  /* A first special case is if S is NULL.  This means put PS in the
     initial state.  */
  if (s == NULL)
    {
      s = buf;
      wc = L'\0';
      temp_state = *data.__statep;
      data.__statep = &temp_state;
    }

  /* Tell where we want to have the result.  */
  data.__outbuf = s;
  data.__outbufend = s + MB_CUR_MAX;

  /* Make sure we use the correct function.  */
  update_conversion_ptrs ();

  /* If WC is the NUL character we write into the output buffer the byte
     sequence necessary for PS to get into the initial state, followed
     by a NUL byte.  */
  if (wc == L'\0')
    {
      status = (*__wcsmbs_gconv_fcts.tomb->__fct) (__wcsmbs_gconv_fcts.tomb,
						   &data, NULL, NULL,
						   &dummy, 1, 1);

      if (status == __GCONV_OK || status == __GCONV_EMPTY_INPUT)
	*data.__outbuf++ = '\0';
    }
  else
    {
      /* Do a normal conversion.  */
      const unsigned char *inbuf = (const unsigned char *) &wc;

      status = (*__wcsmbs_gconv_fcts.tomb->__fct) (__wcsmbs_gconv_fcts.tomb,
						   &data, &inbuf,
						   inbuf + sizeof (wchar_t),
						   &dummy, 0, 1);
    }

  /* There must not be any problems with the conversion but illegal input
     characters.  The output buffer must be large enough, otherwise the
     definition of MB_CUR_MAX is not correct.  All the other possible
     errors also must not happen.  */
  assert (status == __GCONV_OK || status == __GCONV_EMPTY_INPUT
	  || status == __GCONV_ILLEGAL_INPUT
	  || status == __GCONV_INCOMPLETE_INPUT
	  || status == __GCONV_FULL_OUTPUT);

  if (status == __GCONV_OK || status == __GCONV_EMPTY_INPUT
      || status == __GCONV_FULL_OUTPUT)
    result = data.__outbuf - (unsigned char *) s;
  else
    {
      result = (size_t) -1;
      __set_errno (EILSEQ);
    }

  return result;
}
weak_alias (__wcrtomb, wcrtomb)
