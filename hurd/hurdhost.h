/* Host configuration items kept as the whole contents of a file.
Copyright (C) 1996 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/* Fetch and atomically store the contents of the file ITEM.
   Returns the size read or written, or -1 for errors.
   If BUFLEN is not big enough to contain the whole contents,
   BUFLEN bytes of BUF are filled in and we fail with ENAMETOOLONG.  */

ssize_t _hurd_get_host_config (const char *item,
			       char *buf, size_t buflen);
ssize_t _hurd_set_host_config (const char *item,
			       const char *value, size_t valuelen);
