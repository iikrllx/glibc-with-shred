/* Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

#include <endian.h>

#include "localeinfo.h"

/* This table's entries are taken from ISO 14652, the table in section
   4.12 "LC_IDENTIFICATION".  */

const struct locale_data _nl_C_LC_IDENTIFICATION =
{
  _nl_C_name,
  NULL, 0, 0, /* no file mapped */
  UNDELETABLE,
  0,
  NULL,
  16,
  {
    { string: "ISO/IEC 14652 i18n FDCC-set" },
    { string: "ISO/IEC JTC1/SC22/WG20 - internationalization" },
    { string: "C/o Keld Simonsen, Skt. Jorgens Alle 8, DK-1615 Kobenhavn V" },
    { string: "Keld Simonsen" },
    { string: "keld@dkuug.dk" },
    { string: "+45 3122-6543" },
    { string: "+45 3325-6543" },
    { string: "" },
    { string: "ISO" },
    { string: "" },
    { string: "" },
    { string: "" },
    { string: "1.0" },
    { string: "1997-12-20" },
    { string: "i18n:1999\0" "i18n:1999\0" "i18n:1999\0" "i18n:1999\0"
	      "i18n:1999\0" "i18n:1999\0" "\0"          "i18n:1999\0"
	      "i18n:1999\0" "i18n:1999\0" "i18n:1999\0" "i18n:1999\0"
	      "i18n:1999\0" "i18n:1999\0" "i18n:1999\0" "i18n:1999\0"
	      "i18n:1999" },
    { string: _nl_C_codeset }
  }
};
