/* Copyright (C) 1993, 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
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
   02111-1307 USA.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include "strfile.h"

int
_IO_vsscanf (string, format, args)
     const char *string;
     const char *format;
     _IO_va_list args;
{
  int ret;
  _IO_strfile sf;
#ifdef _IO_MTSAFE_IO
  _IO_lock_t lock;
  sf._sbf._f._lock = &lock;
#endif
  _IO_no_init (&sf._sbf._f, 0, -1, NULL, NULL);
  _IO_JUMPS ((struct _IO_FILE_plus *) &sf._sbf) = &_IO_str_jumps;
  _IO_str_init_static (&sf, (char*)string, 0, NULL);
  ret = _IO_vfscanf ((_IO_FILE *) &sf._sbf, format, args, NULL);
  return ret;
}

#ifdef weak_alias
weak_alias (_IO_vsscanf, __vsscanf)
weak_alias (_IO_vsscanf, vsscanf)
#endif
