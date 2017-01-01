/* Copyright (C) 1991-2017 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include "libioP.h"
#include <wchar.h>

wint_t
putwc (wchar_t wc, _IO_FILE *fp)
{
  wint_t result;
  CHECK_FILE (fp, WEOF);
  _IO_acquire_lock (fp);
  result = _IO_putwc_unlocked (wc, fp);
  _IO_release_lock (fp);
  return result;
}
libc_hidden_def (putwc)
