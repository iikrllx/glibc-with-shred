/* Copyright (C) 1993, 1995, 1996, 1997, 1998, 2002, 2003
   Free Software Foundation, Inc.
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
#include <stdio.h>

int
_IO_fflush (fp)
     _IO_FILE *fp;
{
  if (fp == NULL)
    return INTUSE(_IO_flush_all) ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
INTDEF(_IO_fflush)

#ifdef weak_alias
weak_alias (_IO_fflush, fflush)

#ifndef _IO_MTSAFE_IO
weak_alias (_IO_fflush, fflush_unlocked)
libc_hidden_weak (fflush_unlocked)
#endif
#endif
