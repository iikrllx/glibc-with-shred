/* Copyright (C) 1993, 1995, 1996, 1997 Free Software Foundation, Inc.
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

#include "libioP.h"
#include "stdio.h"

int
fileno (fp)
     _IO_FILE* fp;
{
  CHECK_FILE (fp, EOF);

  if (!(fp->_flags & _IO_IS_FILEBUF) || _IO_fileno (fp) < 0)
    {
      __set_errno (EBADF);
      return -1;
    }

  return _IO_fileno (fp);
}

#ifdef _IO_MTSAFE_IO
#ifdef weak_alias
/* The fileno implementation for libio does not require locking because
   it only accesses once a single variable and this is already atomic
   (at least at thread level).  */

weak_alias (fileno, fileno_unlocked)
#endif
#endif
