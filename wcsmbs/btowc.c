/* Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper, <drepper@gnu.ai.mit.edu>

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
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <wcsmbsload.h>


wint_t
btowc (c)
     int c;
{
  char buf[sizeof (wchar_t)];
  struct gconv_step_data data;
  char inbuf[1];
  size_t inbytes;
  size_t converted;
  int status;

  /* If the parameter does not fit into one byte or it is the EOF value
     we can give the answer now.  */
  if (c < -128 || c > 127 || c == EOF)
    return WEOF;

  /* Tell where we want the result.  */
  data.outbuf = (char *) buf;
  data.outbufavail = 0;
  data.outbufsize = sizeof (wchar_t);
  data.is_last = 1;
  data.statep = &data.__state;

  /* Make sure we start in the initial state.  */
  memset (&data.__state, '\0', sizeof (mbstate_t));

  /* Make sure we use the correct function.  */
  update_conversion_ptrs ();

  /* Create the input string.  */
  inbuf[0] = c;
  inbytes = 1;

  status = (*__wcsmbs_gconv_fcts.towc->fct) (__wcsmbs_gconv_fcts.towc,
					     &data, inbuf, &inbytes,
					     &converted, 0);
  /* The conversion failed.  */
  if (status != GCONV_OK && status != GCONV_FULL_OUTPUT)
    return WEOF;

  return *(wchar_t *)buf;
}
