/* Copyright (C) 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Zack Weinberg <zack@rabi.phys.columbia.edu>, 1998.

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

#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>
#include <stdlib.h>

/* Given a fd on a master pseudoterminal, clear a kernel lock so that
   the slave can be opened.  This is to avoid a race between opening the
   master and calling grantpt() to take possession of the slave.  */
int
unlockpt (fd)
     int fd __attribute__ ((unused));
{
#ifdef TIOCSPTLCK
  int serrno = errno;
  int unlock = 0;

  if (__ioctl (fd, TIOCSPTLCK, &unlock))
    {
      if (errno == EINVAL)
	{
	  __set_errno (serrno);
	  return 0;
	}
      else
	return -1;
    }
#endif
  /* On pre-/dev/ptmx kernels this function should be a no-op.  */
  return 0;
}
