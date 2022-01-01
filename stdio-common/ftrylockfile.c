/* Try locking I/O stream.  Singlethreaded version.
   Copyright (C) 1996-2022 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdio-lock.h>
#include <sys/single_threaded.h>

int
__ftrylockfile (FILE *stream)
{
  return _IO_lock_trylock (*stream->_lock);
}
weak_alias (__ftrylockfile, ftrylockfile);
weak_alias (__ftrylockfile, _IO_ftrylockfile)
