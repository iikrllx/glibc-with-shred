/* Copyright (C) 1991, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#include <errno.h>
#include <unistd.h>
#include <hurd.h>
#include <hurd/port.h>
#include <hurd/fd.h>
#include <fcntl.h>

/* Change the current directory to FD.  */

/* XXX should be __fchdir? */
int
fchdir (fd)
     int fd;
{
  error_t err;
  file_t dir;

  err = HURD_DPORT_USE (fd,
			({
			  dir = __file_name_lookup_under (port, "", O_EXEC, 0);
			  dir == MACH_PORT_NULL ? errno : 0;
			}));

  if (! err)
    _hurd_port_set (&_hurd_ports[INIT_PORT_CWDIR], dir);

  return err ? __hurd_fail (err) : 0;
}
