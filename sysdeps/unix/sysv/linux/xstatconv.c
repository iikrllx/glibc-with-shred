/* Convert between the kernel's `struct stat' format, and libc's.
   Copyright (C) 1991, 1995, 1996, 1997 Free Software Foundation, Inc.
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

#include <string.h>


static inline int
xstat_conv (int vers, struct kernel_stat *kbuf, void *ubuf)
{
  switch (vers)
    {
    case _STAT_VER_KERNEL:
      /* Nothing to do.  The struct is in the form the kernel expects.
         We should have short-circuted before we got here, but for
         completeness... */
      *(struct kernel_stat *) ubuf = *kbuf;
      break;

    case _STAT_VER_LINUX:
      {
	struct stat *buf = ubuf;

	/* Convert to current kernel version of `struct stat'.  */
	buf->st_dev = kbuf->st_dev;
#ifdef _HAVE___PAD1
	buf->__pad1 = 0;
#endif
	buf->st_ino = kbuf->st_ino;
	buf->st_mode = kbuf->st_mode;
	buf->st_nlink = kbuf->st_nlink;
	buf->st_uid = kbuf->st_uid;
	buf->st_gid = kbuf->st_gid;
	buf->st_rdev = kbuf->st_rdev;
#ifdef _HAVE___PAD2
	buf->__pad2 = 0;
#endif
	buf->st_size = kbuf->st_size;
	buf->st_blksize = kbuf->st_blksize;
	buf->st_blocks = kbuf->st_blocks;
	buf->st_atime = kbuf->st_atime;
#ifdef _HAVE___UNUSED1
	buf->__unused1 = 0;
#endif
	buf->st_mtime = kbuf->st_mtime;
#ifdef _HAVE___UNUSED2
	buf->__unused2 = 0;
#endif
	buf->st_ctime = kbuf->st_ctime;
#ifdef _HAVE___UNUSED3
	buf->__unused3 = 0;
#endif
#ifdef _HAVE___UNUSED4
	buf->__unused4 = 0;
#endif
#ifdef _HAVE___UNUSED5
	buf->__unused5 = 0;
#endif
      }
      break;

    default:
      __set_errno (EINVAL);
      return -1;
    }

  return 0;
}

static inline int
xstat64_conv (int vers, struct kernel_stat *kbuf, void *ubuf)
{
#ifdef XSTAT_IS_XSTAT64
  return xstat_conv (vers, kbuf, ubuf);
#else
  switch (vers)
    {
    case _STAT_VER_LINUX:
      {
	struct stat64 *buf = ubuf;

	/* Convert to current kernel version of `struct stat64'.  */
	buf->st_dev = kbuf->st_dev;
#ifdef _HAVE___PAD1
	buf->__pad1 = 0;
#endif
	buf->st_ino = kbuf->st_ino;
	buf->st_mode = kbuf->st_mode;
	buf->st_nlink = kbuf->st_nlink;
	buf->st_uid = kbuf->st_uid;
	buf->st_gid = kbuf->st_gid;
	buf->st_rdev = kbuf->st_rdev;
#ifdef _HAVE___PAD2
	buf->__pad2 = 0;
#endif
	buf->st_size = kbuf->st_size;
	buf->st_blksize = kbuf->st_blksize;
	buf->st_blocks = kbuf->st_blocks;
	buf->st_atime = kbuf->st_atime;
#ifdef _HAVE___UNUSED1
	buf->__unused1 = 0;
#endif
	buf->st_mtime = kbuf->st_mtime;
#ifdef _HAVE___UNUSED2
	buf->__unused2 = 0;
#endif
	buf->st_ctime = kbuf->st_ctime;
#ifdef _HAVE___UNUSED3
	buf->__unused3 = 0;
#endif
#ifdef _HAVE___UNUSED4
	buf->__unused4 = 0;
#endif
#ifdef _HAVE___UNUSED5
	buf->__unused5 = 0;
#endif
      }
      break;

      /* If struct stat64 is different from struct stat then
	 _STAT_VER_KERNEL does not make sense.  */
    case _STAT_VER_KERNEL:
    default:
      __set_errno (EINVAL);
      return -1;
    }

  return 0;
#endif
}
