/* Copyright (C) 2000, 2003, 2005 Free Software Foundation, Inc.
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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>

/* Reserve storage for the data of the file associated with FD.  */

int
posix_fallocate (int fd, __off_t offset, __off_t len)
{
  struct stat64 st;
  struct statfs f;

  /* `off_t' is a signed type.  Therefore we can determine whether
     OFFSET + LEN is too large if it is a negative value.  */
  if (offset < 0 || len < 0)
    return EINVAL;
  if (offset + len < 0)
    return EFBIG;

  /* First thing we have to make sure is that this is really a regular
     file.  */
  if (__fxstat64 (_STAT_VER, fd, &st) != 0)
    return EBADF;
  if (S_ISFIFO (st.st_mode))
    return ESPIPE;
  if (! S_ISREG (st.st_mode))
    return ENODEV;

  if (len == 0)
    {
      if (st.st_size < offset)
	{
	  int ret = __ftruncate (fd, offset);

	  if (ret != 0)
	    ret = errno;
	  return ret;
	}
      return 0;
    }

  /* We have to know the block size of the filesystem to get at least some
     sort of performance.  */
  if (__fstatfs (fd, &f) != 0)
    return errno;

  /* Try to play safe.  */
  if (f.f_bsize == 0)
    f.f_bsize = 512;

  /* Write something to every block.  */
  for (offset += (len - 1) % f.f_bsize; len > 0; offset += f.f_bsize)
    {
      len -= f.f_bsize;

      if (offset < st.st_size)
	{
	  unsigned char c;
	  ssize_t rsize = __pread (fd, &c, 1, offset);

	  if (rsize < 0)
	    return errno;
	  /* If there is a non-zero byte, the block must have been
	     allocated already.  */
	  else if (rsize == 1 && c != 0)
	    continue;
	}

      if (__pwrite (fd, "", 1, offset) != 1)
	return errno;
    }

  return 0;
}
