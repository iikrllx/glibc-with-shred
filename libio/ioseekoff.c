/* Copyright (C) 1993, 1997, 1998 Free Software Foundation, Inc.
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

#include <libioP.h>

_IO_fpos64_t
_IO_seekoff (fp, offset, dir, mode)
     _IO_FILE *fp;
     _IO_off64_t offset;
     int dir;
     int mode;
{
  _IO_fpos64_t retval;

  /* If we have a backup buffer, get rid of it, since the __seekoff
     callback may not know to do the right thing about it.
     This may be over-kill, but it'll do for now. TODO */
  _IO_cleanup_region_start ((void (*) __P ((void *))) _IO_funlockfile, fp);
  _IO_flockfile (fp);


  if (_IO_have_backup (fp))
    {
      if (dir == _IO_seek_cur && _IO_in_backup (fp))
	offset -= fp->_IO_read_end - fp->_IO_read_ptr;
      _IO_free_backup_area (fp);
    }
  retval = _IO_SEEKOFF (fp, offset, dir, mode);

  _IO_funlockfile (fp);
  _IO_cleanup_region_end (0);
  return retval;
}
