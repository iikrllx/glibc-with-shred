/* Copyright (C) 1992, 1997, 2002 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.  */

#include <termios.h>
#include <sysv_termio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

/* Return the foreground process group ID of FD.  */
pid_t
tcgetpgrp (fd)
     int fd;
{
  int pgrp;
  if (__ioctl (fd, _TIOCGPGRP, &pgrp) < 0)
    return (pid_t) -1;
  return (pid_t) pgrp;
}
libc_hidden_def (tcgetpgrp)
