/* Find matching transformation algorithms and initialize steps.
   Copyright (C) 1997, 1998 Free Software Foundation, Inc.
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

#include <errno.h>
#include <stdlib.h>

#include <gconv_int.h>


int
internal_function
__gconv_open (const char *toset, const char *fromset, gconv_t *handle)
{
  struct gconv_step *steps;
  size_t nsteps;
  gconv_t result = NULL;
  size_t cnt = 0;
  int res;

  res = __gconv_find_transform (toset, fromset, &steps, &nsteps);
  if (res == GCONV_OK)
    {
      /* Allocate room for handle.  */
      result = (gconv_t) malloc (sizeof (struct gconv_info));
      if (result == NULL)
	res = GCONV_NOMEM;
      else
	{
	  /* Remember the list of steps.  */
	  result->steps = steps;
	  result->nsteps = nsteps;

	  /* Allocate array for the step data.  */
	  result->data = (struct gconv_step_data *)
	    calloc (nsteps, sizeof (struct gconv_step_data));

	  if (result->data == NULL)
	    res = GCONV_NOMEM;
	  else
	    {
	      /* Call all initialization functions for the transformation
		 step implemenations.  */
	      struct gconv_step_data *data = result->data;

	      for (cnt = 0; cnt < nsteps; ++cnt)
		{
		  /* If this is the last step we must not allocate an output
		     buffer.  Signal this to the initializer.  */
		  data[cnt].is_last = cnt == nsteps - 1;

		  /* We use the `mbstate_t' member in DATA.  */
		  data[cnt].statep = &data[cnt].__state;

		  /* Allocate the buffer.  */
		  data[cnt].outbufsize = GCONV_DEFAULT_BUFSIZE;
		  data[cnt].outbuf = (char *) malloc (data[cnt].outbufsize);
		  if (data[cnt].outbuf == NULL)
		    {
		      res = GCONV_NOMEM;
		      break;
		    }
		  data[cnt].outbufavail = 0;
		}
	    }
	}
    }

  if (res != GCONV_OK)
    {
      /* Something went wrong.  Free all the resources.  */
      int serrno = errno;

      if (result != NULL)
	{
	  if (result->data != NULL)
	    {
	      while (cnt-- > 0)
		free (result->data[cnt].outbuf);

	      free (result->data);
	    }

	  free (result);
	  result = NULL;
	}

      __gconv_close_transform (steps, nsteps);

      __set_errno (serrno);
    }

  *handle = result;
  return res;
}
