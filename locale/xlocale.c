/* C locale object.
   Copyright (C) 2001, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 2001.

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

#include <locale.h>
#include "localeinfo.h"

#define DEFINE_CATEGORY(category, category_name, items, a) \
extern struct locale_data _nl_C_##category;
#include "categories.def"
#undef	DEFINE_CATEGORY

/* Defined in locale/C-ctype.c.  */
extern const char _nl_C_LC_CTYPE_class[] attribute_hidden;
extern const char _nl_C_LC_CTYPE_toupper[] attribute_hidden;
extern const char _nl_C_LC_CTYPE_tolower[] attribute_hidden;


#define NL_C_INITIALIZER						      \
  {									      \
    .__locales =							      \
    {									      \
      [LC_CTYPE] = &_nl_C_LC_CTYPE,					      \
      [LC_NUMERIC] = &_nl_C_LC_NUMERIC,					      \
      [LC_TIME] = &_nl_C_LC_TIME,					      \
      [LC_COLLATE] = &_nl_C_LC_COLLATE,					      \
      [LC_MONETARY] = &_nl_C_LC_MONETARY,				      \
      [LC_MESSAGES] = &_nl_C_LC_MESSAGES,				      \
      [LC_PAPER] = &_nl_C_LC_PAPER,					      \
      [LC_NAME] = &_nl_C_LC_NAME,					      \
      [LC_ADDRESS] = &_nl_C_LC_ADDRESS,					      \
      [LC_TELEPHONE] = &_nl_C_LC_TELEPHONE,				      \
      [LC_MEASUREMENT] = &_nl_C_LC_MEASUREMENT,				      \
      [LC_IDENTIFICATION] = &_nl_C_LC_IDENTIFICATION			      \
    },									      \
    .__ctype_b = (const unsigned short int *) _nl_C_LC_CTYPE_class + 128,     \
    .__ctype_tolower = (const int *) _nl_C_LC_CTYPE_tolower + 128,	      \
    .__ctype_toupper = (const int *) _nl_C_LC_CTYPE_toupper + 128	      \
  }

struct __locale_struct _nl_C_locobj attribute_hidden = NL_C_INITIALIZER;

#ifdef SHARED
struct __locale_struct _nl_global_locale attribute_hidden = NL_C_INITIALIZER;

# if USE_TLS && HAVE___THREAD
/* The tsd macros don't permit an initializer.  */
__thread void *__libc_tsd_LOCALE = &_nl_global_locale;
# else
__libc_tsd_define (, LOCALE)
/* This is a bad kludge presuming the variable name used by the macros.
   Using typeof makes sure to barf if we do not match the macro definition.  */
__typeof (__libc_tsd_LOCALE_data) __libc_tsd_LOCALE_data = &_nl_global_locale;
# endif

#endif
