/* Copyright (C) 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU IO Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This library is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this library; see the file COPYING.  If not, write to
   the Free Software Foundation, 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA.

   As a special exception, if you link this library with files
   compiled with a GNU compiler to produce an executable, this does
   not cause the resulting executable to be covered by the GNU General
   Public License.  This exception does not however invalidate any
   other reasons why the executable file might be covered by the GNU
   General Public License.  */

#include <libioP.h>
#ifdef _LIBC
# include <wchar.h>
#endif
#include <stdlib.h>
#include <string.h>

#ifdef _LIBC
# include <langinfo.h>
# include <locale/localeinfo.h>
# include <wcsmbs/wcsmbsload.h>
#endif


/* Prototypes of libio's codecvt functions.  */
static enum __codecvt_result do_out (struct _IO_codecvt *codecvt,
				     __mbstate_t *statep,
				     const wchar_t *from_start,
				     const wchar_t *from_end,
				     const wchar_t **from_stop, char *to_start,
				     char *to_end, char **to_stop);
static enum __codecvt_result do_unshift (struct _IO_codecvt *codecvt,
					 __mbstate_t *statep, char *to_start,
					 char *to_end, char **to_stop);
static enum __codecvt_result do_in (struct _IO_codecvt *codecvt,
				    __mbstate_t *statep,
				    const char *from_start,
				    const char *from_end,
				    const char **from_stop, wchar_t *to_start,
				    wchar_t *to_end, wchar_t **to_stop);
static int do_encoding (struct _IO_codecvt *codecvt);
static int do_length (struct _IO_codecvt *codecvt, __mbstate_t *statep,
		      const char *from_start,
		      const char *from_end, _IO_size_t max);
static int do_max_length (struct _IO_codecvt *codecvt);
static int do_always_noconv (struct _IO_codecvt *codecvt);


/* The functions used in `codecvt' for libio are always the same.  */
struct _IO_codecvt __libio_codecvt =
{
  .__codecvt_destr = NULL,		/* Destructor, never used.  */
  .__codecvt_do_out = do_out,
  .__codecvt_do_unshift = do_unshift,
  .__codecvt_do_in = do_in,
  .__codecvt_do_encoding = do_encoding,
  .__codecvt_do_always_noconv = do_always_noconv,
  .__codecvt_do_length = do_length,
  .__codecvt_do_max_length = do_max_length
};


/* Return orientation of stream.  If mode is nonzero try to change
   the orientation first.  */
#undef _IO_fwide
int
_IO_fwide (fp, mode)
     _IO_FILE *fp;
     int mode;
{
  /* Normalize the value.  */
  mode = mode < 0 ? -1 : (mode == 0 ? 0 : 1);

  if (mode == 0 || fp->_mode != 0)
    /* The caller simply wants to know about the current orientation
       or the orientation already has been determined.  */
    return fp->_mode;

  _IO_cleanup_region_start ((void (*) __P ((void *))) _IO_funlockfile, fp);
  _IO_flockfile (fp);

  /* Set the orientation appropriately.  */
  if (mode > 0)
    {
      fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_read_end;
      fp->_wide_data->_IO_write_ptr = fp->_wide_data->_IO_write_base;

      /* Clear the state.  We start all over again.  */
      memset (&fp->_wide_data->_IO_state, '\0', sizeof (__mbstate_t));
      memset (&fp->_wide_data->_IO_last_state, '\0', sizeof (__mbstate_t));

      /* Get the character conversion functions based on the currently
	 selected locale for LC_CTYPE.  */
#ifdef _LIBC
      {
	struct gconv_fcts fcts;
	struct _IO_codecvt *cc = &fp->_wide_data->_codecvt;

	__wcsmbs_clone_conv (&fcts);

	/* The functions are always the same.  */
	*cc = __libio_codecvt;

	cc->__cd_in.__cd.__nsteps = 1; /* Only one step allowed.  */
	cc->__cd_in.__cd.__steps = fcts.towc;

	cc->__cd_in.__cd.__data[0].__invocation_counter = 0;
	cc->__cd_in.__cd.__data[0].__internal_use = 1;
	cc->__cd_in.__cd.__data[0].__is_last = 1;
	cc->__cd_in.__cd.__data[0].__statep = &fp->_wide_data->_IO_state;

	cc->__cd_out.__cd.__nsteps = 1; /* Only one step allowed.  */
	cc->__cd_out.__cd.__steps = fcts.tomb;

	cc->__cd_out.__cd.__data[0].__invocation_counter = 0;
	cc->__cd_out.__cd.__data[0].__internal_use = 1;
	cc->__cd_out.__cd.__data[0].__is_last = 1;
	cc->__cd_out.__cd.__data[0].__statep = &fp->_wide_data->_IO_state;
      }
#else
# error "somehow determine this from LC_CTYPE"
#endif

      /* From now on use the wide character callback functions.  */
      ((struct _IO_FILE_plus *) fp)->vtable = fp->_wide_data->_wide_vtable;
    }

  /* Set the mode now.  */
  fp->_mode = mode;

  _IO_funlockfile (fp);
  _IO_cleanup_region_end (0);

  return mode;
}

#ifdef weak_alias
weak_alias (_IO_fwide, fwide)
#endif


static enum __codecvt_result
do_out (struct _IO_codecvt *codecvt, __mbstate_t *statep,
	const wchar_t *from_start, const wchar_t *from_end,
	const wchar_t **from_stop, char *to_start, char *to_end,
	char **to_stop)
{
  enum __codecvt_result result;

#ifdef _LIBC
  struct __gconv_step *gs = codecvt->__cd_out.__cd.__steps;
  int status;
  size_t written;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_out.__cd.__data[0].__outbuf = to_start;
  codecvt->__cd_out.__cd.__data[0].__outbufend = to_end;
  codecvt->__cd_out.__cd.__data[0].__statep = statep;

  status = (*gs->__fct) (gs, codecvt->__cd_out.__cd.__data, &from_start_copy,
			 (const unsigned char *) from_end, &written, 0, 0);

  *from_stop = (wchar_t *) from_start_copy;
  *to_stop = codecvt->__cd_out.__cd.__data[0].__outbuf;

  switch (status)
    {
    case __GCONV_OK:
    case __GCONV_EMPTY_INPUT:
      result = __codecvt_ok;
      break;

    case __GCONV_FULL_OUTPUT:
    case __GCONV_INCOMPLETE_INPUT:
      result = __codecvt_partial;
      break;

    default:
      result = __codecvt_error;
      break;
    }
#else
  /* Decide what to do.  */
  result = __codecvt_error;
#endif

  return result;
}


static enum __codecvt_result
do_unshift (struct _IO_codecvt *codecvt, __mbstate_t *statep,
	    char *to_start, char *to_end, char **to_stop)
{
  enum __codecvt_result result;

#ifdef _LIBC
  struct __gconv_step *gs = codecvt->__cd_out.__cd.__steps;
  int status;
  size_t written;

  codecvt->__cd_out.__cd.__data[0].__outbuf = to_start;
  codecvt->__cd_out.__cd.__data[0].__outbufend = to_end;
  codecvt->__cd_out.__cd.__data[0].__statep = statep;

  status = (*gs->__fct) (gs, codecvt->__cd_out.__cd.__data, NULL, NULL,
			 &written, 1, 0);

  *to_stop = codecvt->__cd_out.__cd.__data[0].__outbuf;

  switch (status)
    {
    case __GCONV_OK:
    case __GCONV_EMPTY_INPUT:
      result = __codecvt_ok;
      break;

    case __GCONV_FULL_OUTPUT:
    case __GCONV_INCOMPLETE_INPUT:
      result = __codecvt_partial;
      break;

    default:
      result = __codecvt_error;
      break;
    }
#else
  /* Decide what to do.  */
  result = __codecvt_error;
#endif

  return result;
}


static enum __codecvt_result
do_in (struct _IO_codecvt *codecvt, __mbstate_t *statep,
       const char *from_start, const char *from_end, const char **from_stop,
       wchar_t *to_start, wchar_t *to_end, wchar_t **to_stop)
{
  enum __codecvt_result result;

#ifdef _LIBC
  struct __gconv_step *gs = codecvt->__cd_in.__cd.__steps;
  int status;
  size_t written;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_in.__cd.__data[0].__outbuf = (char *) to_start;
  codecvt->__cd_in.__cd.__data[0].__outbufend = (char *) to_end;
  codecvt->__cd_in.__cd.__data[0].__statep = statep;

  status = (*gs->__fct) (gs, codecvt->__cd_in.__cd.__data, &from_start_copy,
			 from_end, &written, 0, 0);

  *from_stop = from_start_copy;
  *to_stop = (wchar_t *) codecvt->__cd_in.__cd.__data[0].__outbuf;

  switch (status)
    {
    case __GCONV_OK:
    case __GCONV_EMPTY_INPUT:
      result = __codecvt_ok;
      break;

    case __GCONV_FULL_OUTPUT:
    case __GCONV_INCOMPLETE_INPUT:
      result = __codecvt_partial;
      break;

    default:
      result = __codecvt_error;
      break;
    }
#else
  /* Decide what to do.  */
  result = __codecvt_error;
#endif

  return result;
}


static int
do_encoding (struct _IO_codecvt *codecvt)
{
#ifdef _LIBC
  /* See whether the encoding is stateful.  */
  if (codecvt->__cd_in.__cd.__steps[0].__stateful)
    return -1;
  /* Fortunately not.  Now determine the input bytes for the conversion
     necessary for each wide character.  */
  if (codecvt->__cd_in.__cd.__steps[0].__min_needed_from
      != codecvt->__cd_in.__cd.__steps[0].__max_needed_from)
    /* Not a constant value.  */
    return 0;

  return codecvt->__cd_in.__cd.__steps[0].__min_needed_from;
#else
  /* Worst case scenario.  */
  return -1;
#endif
}


static int
do_always_noconv (struct _IO_codecvt *codecvt)
{
  return 0;
}


static int
do_length (struct _IO_codecvt *codecvt, __mbstate_t *statep,
	   const char *from_start, const char *from_end, _IO_size_t max)
{
  int result;
#ifdef _LIBC
  const unsigned char *cp = (const unsigned char *) from_start;
  wchar_t to_buf[max];
  struct __gconv_step *gs = codecvt->__cd_in.__cd.__steps;
  int status;
  size_t written;

  codecvt->__cd_in.__cd.__data[0].__outbuf = (char *) to_buf;
  codecvt->__cd_in.__cd.__data[0].__outbufend = (char *) &to_buf[max];
  codecvt->__cd_in.__cd.__data[0].__statep = statep;

  status = (*gs->__fct) (gs, codecvt->__cd_in.__cd.__data, &cp, from_end,
			 &written, 0, 0);

  result = cp - (const unsigned char *) from_start;
#else
  /* Decide what to do.  */
  result = 0;
#endif

  return result;
}


static int
do_max_length (struct _IO_codecvt *codecvt)
{
#ifdef _LIBC
  return codecvt->__cd_in.__cd.__steps[0].__max_needed_from;
#else
  return MB_CUR_MAX;
#endif
}
