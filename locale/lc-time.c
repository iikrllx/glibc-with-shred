/* Define current locale data for LC_TIME category.
   Copyright (C) 1995, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#include <bits/libc-lock.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include "localeinfo.h"

_NL_CURRENT_DEFINE (LC_TIME);

/* Some of the functions here must not be used while setlocale is called.  */
__libc_lock_define (extern, __libc_setlocale_lock)


static int era_initialized;
static struct era_entry **eras;
static size_t num_eras;


static int alt_digits_initialized;
static const char **alt_digits;


static int walt_digits_initialized;
static const wchar_t **walt_digits;


void
_nl_postload_time (void)
{
  /* Prepare lazy initialization of `era' and `alt_digits' array.  */
  era_initialized = 0;
  alt_digits_initialized = 0;
  walt_digits_initialized = 0;
}


struct era_entry *
_nl_get_era_entry (const struct tm *tp)
{
  struct era_entry *result;
  size_t cnt;

  __libc_lock_lock (__libc_setlocale_lock);

  if (era_initialized == 0)
    {
      size_t new_num_eras = _NL_CURRENT_WORD (LC_TIME,
					      _NL_TIME_ERA_NUM_ENTRIES);

      if (eras != NULL && new_num_eras == 0)
	{
	  free (eras);
	  eras = NULL;
	}
      else if (new_num_eras != 0)
	{
	  if (num_eras != new_num_eras)
	    eras = realloc (eras, new_num_eras * sizeof (struct era_entry *));

	  if (eras == NULL)
	    num_eras = 0;
	  else
	    {
	      const char *ptr = _NL_CURRENT (LC_TIME, _NL_TIME_ERA_ENTRIES);
	      num_eras = new_num_eras;

	      for (cnt = 0; cnt < num_eras; ++cnt)
		{
		  eras[cnt] = (struct era_entry *) ptr;

		  /* Skip numeric values.  */
		  ptr += sizeof (struct era_entry);
		  /* Skip era name.  */
		  ptr = strchr (ptr, '\0') + 1;
		  /* Skip era format.  */
		  ptr = strchr (ptr, '\0') + 1;

		  ptr += 3 - (((ptr - (const char *) eras[cnt]) + 3) & 3);

		  /* Skip wide era name.  */
		  ptr = (char *) wcschr ((wchar_t *) ptr, '\0');
		  /* Skip wide era format.  */
		  ptr = (char *) wcschr ((wchar_t *) ptr, '\0');
		}
	    }
	}

      era_initialized = 1;
    }

  /* Now compare date with the available eras.  */
  for (cnt = 0; cnt < num_eras; ++cnt)
    if ((eras[cnt]->start_date[0] < tp->tm_year
	 || (eras[cnt]->start_date[0] == tp->tm_year
	     && (eras[cnt]->start_date[1] < tp->tm_mon
		 || (eras[cnt]->start_date[1] == tp->tm_mon
		     && eras[cnt]->start_date[2] <= tp->tm_mday))))
	&& (eras[cnt]->stop_date[0] > tp->tm_year
	    || (eras[cnt]->stop_date[0] == tp->tm_year
		&& (eras[cnt]->stop_date[1] > tp->tm_mon
		    || (eras[cnt]->stop_date[1] == tp->tm_mon
			&& eras[cnt]->stop_date[2] >= tp->tm_mday)))))
      break;

  result = cnt < num_eras ? eras[cnt] : NULL;

  __libc_lock_unlock (__libc_setlocale_lock);

  return result;
}


const char *
_nl_get_alt_digit (unsigned int number)
{
  const char *result;

  __libc_lock_lock (__libc_setlocale_lock);

  if (alt_digits_initialized == 0)
    {
      alt_digits_initialized = 1;

      if (alt_digits == NULL)
	alt_digits = malloc (100 * sizeof (const char *));

      if (alt_digits != NULL)
	{
	  const char *ptr = _NL_CURRENT (LC_TIME, ALT_DIGITS);
	  size_t cnt;

	  if (alt_digits != NULL)
	    for (cnt = 0; cnt < 100; ++cnt)
	      {
		alt_digits[cnt] = ptr;

		/* Skip digit format. */
		ptr = strchr (ptr, '\0') + 1;
	      }
	}
    }

  result = alt_digits != NULL && number < 100 ? alt_digits[number] : NULL;

  __libc_lock_unlock (__libc_setlocale_lock);

  return result;
}


const wchar_t *
_nl_get_walt_digit (unsigned int number)
{
  const wchar_t *result;

  __libc_lock_lock (__libc_setlocale_lock);

  if (walt_digits_initialized == 0)
    {
      walt_digits_initialized = 1;

      if (walt_digits == NULL)
	walt_digits = malloc (100 * sizeof (const uint32_t *));

      if (walt_digits != NULL)
	{
	  const wchar_t *ptr = _NL_CURRENT_WSTR (LC_TIME, _NL_WALT_DIGITS);
	  size_t cnt;

	  for (cnt = 0; cnt < 100; ++cnt)
	    {
	      walt_digits[cnt] = ptr;

	      /* Skip digit format. */
	      ptr = wcschr (ptr, L'\0') + 1;
	    }
	}
    }

  result = walt_digits != NULL && number < 100 ? walt_digits[number] : NULL;

  __libc_lock_unlock (__libc_setlocale_lock);

  return (wchar_t *) result;
}
