/* Define current locale data for LC_CTYPE category.
   Copyright (C) 1995-1999, 2000, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#include "localeinfo.h"
#include <ctype.h>
#include <endian.h>
#include <stdint.h>

_NL_CURRENT_DEFINE (LC_CTYPE);

/* We are called after loading LC_CTYPE data to load it into
   the variables used by the ctype.h macros.  */

void
_nl_postload_ctype (void)
{
#define current(type,x,offset) \
  ((const type *) _NL_CURRENT (LC_CTYPE, _NL_CTYPE_##x) + offset)

/* These are defined in ctype-info.c.
   The declarations here must match those in localeinfo.h.

   These point into arrays of 384, so they can be indexed by any `unsigned
   char' value [0,255]; by EOF (-1); or by any `signed char' value
   [-128,-1).  ISO C requires that the ctype functions work for `unsigned
   char' values and for EOF; we also support negative `signed char' values
   for broken old programs.  The case conversion arrays are of `int's
   rather than `unsigned char's because tolower (EOF) must be EOF, which
   doesn't fit into an `unsigned char'.  But today more important is that
   the arrays are also used for multi-byte character sets.  */

  if (_NL_CURRENT_LOCALE == &_nl_global_locale)
    {
      __libc_tsd_set (CTYPE_B, (void *) current (uint16_t, CLASS, 128));
      __libc_tsd_set (CTYPE_TOUPPER, (void *) current (int32_t, TOUPPER, 128));
      __libc_tsd_set (CTYPE_TOLOWER, (void *) current (int32_t, TOLOWER, 128));
    }

#include <shlib-compat.h>
#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_3)
  extern __const unsigned short int *__ctype_old_b; /* Characteristics.  */
  extern __const __int32_t *__ctype_old_tolower; /* Case conversions.  */
  extern __const __int32_t *__ctype_old_toupper; /* Case conversions.  */

  extern const uint32_t *__ctype32_old_b;
  extern const uint32_t *__ctype32_old_toupper;
  extern const uint32_t *__ctype32_old_tolower;

  __ctype_old_b = current (uint16_t, CLASS, 128);
  __ctype_old_toupper = current (uint32_t, TOUPPER, 128);
  __ctype_old_tolower = current (uint32_t, TOLOWER, 128);
  __ctype32_old_b = current (uint32_t, CLASS32, 0);
  __ctype32_old_toupper = current (uint32_t, TOUPPER32, 0);
  __ctype32_old_tolower = current (uint32_t, TOLOWER32, 0);
#endif
}
