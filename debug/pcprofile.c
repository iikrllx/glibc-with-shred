/* Profile PC and write result to FIFO.
   Copyright (C) 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1999.

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

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/* Nonzero if we are actually doing something.  */
static int active;

/* The file descriptor of the FIFO.  */
static int fd;


static void
__attribute__ ((constructor))
install (void)
{
  /* See whether the environment variable `PCPROFILE_OUTPUT' is defined.
     If yes, it should name a FIFO.  We open it and mark ourself as active.  */
  const char *outfile = getenv ("PCPROFILE_OUTPUT");

  if (outfile != NULL && *outfile != '\0')
    {
      fd = open (outfile, O_RDWR);

      if (fd != -1)
	active = 1;
    }
}


static void
__attribute__ ((destructor))
uninstall (void)
{
  if (active)
    close (fd);
}


void
__cyg_profile_func_enter (void *this_fn, void *call_site)
{
  void *buf[2];

  if (! active)
    return;

  /* Now write out the current position and that of the caller.  We do
     this now, and don't cache the because we want real-time output.  */
  buf[0] = this_fn;
  buf[1] = call_site;

  write (fd, buf, sizeof buf);
}
/* We don't handle entry and exit differently here.  */
strong_alias (__cyg_profile_func_enter, __cyg_profile_func_exit)
