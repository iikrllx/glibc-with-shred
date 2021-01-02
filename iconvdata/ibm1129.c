/* Conversion from and to IBM1129.
   Copyright (C) 2000-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Masahide Washizawa <washi@jp.ibm.com>, 2000.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <stdint.h>

/* Get the conversion table.  */
#define TABLES <ibm1129.h>

#define CHARSET_NAME   "IBM1129//"
#define HAS_HOLES  0   /* All 256 character are defined.  */

#include <8bit-gap.c>
