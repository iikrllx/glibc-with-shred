/* Copyright (C) 2007, 2009 Free Software Foundation, Inc.
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
   02111-1307 USA.  */

#include <fcntl.h>
#include <sysdep.h>


/* Reserve storage for the data of the file associated with FD.  */
int
__fallocate64_l64 (int fd, int mode, __off64_t offset, __off64_t len)
{
  return INLINE_SYSCALL (fallocate, 6, fd, mode,
			 __LONG_LONG_PAIR ((long int) (offset >> 32),
					   (long int) offset),
			 __LONG_LONG_PAIR ((long int) (len >> 32),
					   (long int) len));
}
