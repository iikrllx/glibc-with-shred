/* Copyright (C) 1993, 1997 Free Software Foundation, Inc.
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
#ifdef __STDC__
#include <stdlib.h>
#endif

_IO_FILE *
_IO_new_fopen (filename, mode)
     const char *filename;
     const char *mode;
{
  struct locked_FILE
  {
    struct _IO_FILE_complete fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.plus.file._lock = &new_f->lock;
#endif
  _IO_init (&new_f->fp.plus.file, 0);
  _IO_JUMPS (&new_f->fp.plus.file) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp.plus.file);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.plus.vtable = NULL;
#endif
  if (_IO_file_fopen (&new_f->fp.plus.file, filename, mode, 0) != NULL)
        return (_IO_FILE *) &new_f->fp.plus;
  _IO_un_link (&new_f->fp.plus.file);
  free (new_f);
  return NULL;
}

#ifdef DO_VERSIONING
strong_alias (_IO_new_fopen, __new_fopen)
symbol_version (_IO_new_fopen, _IO_fopen, GLIBC_2.1);
symbol_version (__new_fopen, fopen, GLIBC_2.1);
#else
# ifdef weak_alias
weak_symbol (_IO_new_fopen, _IO_fopen)
weak_symbol (_IO_new_fopen, fopen)
# endif
#endif
