/* writev supports all Linux kernels >= 2.0.
   Copyright (C) 1997 Free Software Foundation, Inc.
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
#include <stddef.h>
#include <sys/param.h>
#include <sys/uio.h>

extern ssize_t __syscall_writev __P ((int, const struct iovec *, int));

/* Not all versions of the kernel support the large number of records.  */
#undef MAX_IOVEC
#ifdef UIO_FASTIOV
# define MAX_IOVEC	UIO_FASTIOV
#else
# define MAX_IOVEC	8	/* 8 is a safe number. */
#endif


/* We should deal with kernel which have a smaller UIO_MAXIOV as well
   as a very big count.  */
ssize_t
writev (fd, vector, count)
     int fd;
     const struct iovec *vector;
     int count;
{
  int errno_saved = errno;
  ssize_t bytes_written;

  bytes_written = __syscall_writev (fd, vector, count);

  if (bytes_written < 0 && errno == EINVAL && count > MAX_IOVEC)
    {
      int i;

      /* Restore the old error value as if nothing happened.  */
      __set_errno (errno_saved);

      bytes_written = 0;
      for (i = 0; i < count; i += MAX_IOVEC)
	{
	  ssize_t bytes = __syscall_writev (fd, vector + i,
					    MIN (count - i, MAX_IOVEC));

	  if (bytes < 0)
	    return bytes_written > 0 ? bytes_written : bytes;
	}
    }

  return bytes_written;
}
