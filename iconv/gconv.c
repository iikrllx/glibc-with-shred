/* Convert characters in input buffer using conversion descriptor to
   output buffer.
   Copyright (C) 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <assert.h>
#include <gconv.h>
#include <sys/param.h>
#include <dlfcn.h>

int
internal_function
__gconv (__gconv_t cd, const unsigned char **inbuf,
	 const unsigned char *inbufend, unsigned char **outbuf,
	 unsigned char *outbufend, size_t *converted)
{
  size_t last_step = cd->__nsteps - 1;
  int result;

  if (cd == (__gconv_t) -1L)
    return __GCONV_ILLEGAL_DESCRIPTOR;

  assert (converted != NULL);
  *converted = 0;

  cd->__data[last_step].__outbuf = outbuf != NULL ? *outbuf : NULL;
  cd->__data[last_step].__outbufend = outbufend;

  if (inbuf == NULL || *inbuf == NULL)
    /* We just flush.  */
    result = DL_CALL_FCT (cd->__steps->__fct,
			   (cd->__steps, cd->__data, NULL, NULL,
			    converted, 1));
  else
    {
      const unsigned char *last_start;

      assert (outbuf != NULL && *outbuf != NULL);

      do
	{
	  last_start = *inbuf;
	  result = DL_CALL_FCT (cd->__steps->__fct,
				 (cd->__steps, cd->__data, inbuf, inbufend,
				  converted, 0));
	}
      while (result == __GCONV_EMPTY_INPUT && last_start != *inbuf
	     && *inbuf + cd->__steps->__min_needed_from <= inbufend);
    }

  if (outbuf != NULL && *outbuf != NULL)
    *outbuf = cd->__data[last_step].__outbuf;

  return result;
}
