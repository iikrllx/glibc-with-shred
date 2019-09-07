/* Copyright (C) 2005-2019 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <sys/stat.h>


/* Create a new FIFO with permission bits MODE.  But interpret
   relative PATH names relative to the directory associated with FD.  */
int
mkfifoat (int fd, const char *file, mode_t mode)
{
  dev_t dev = 0;
  return __xmknodat (_MKNOD_VER, fd, file, mode | S_IFIFO, &dev);
}
