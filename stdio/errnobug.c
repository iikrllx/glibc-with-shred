/* Regression test for reported old bug that errno is clobbered
   by the first successful output to a stream on an unseekable object. 
Copyright (C) 1995 Free Software Foundation, Inc.
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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int
main (void)
{
  int fd[2];
  FILE *f;

  /* Get a stream that cannot seek.  */

  if (pipe (fd))
    {
      perror ("pipe");
      return 1;
    }
  f = fdopen (fd[1], "w");
  if (f == NULL)
    {
      perror ("fdopen");
      return 1;
    }

  errno = 0;
  if (fputs ("fnord", f))
    {
      perror ("fputs");
      return 1;
    }

  if (errno)
    {
      perror ("errno gratuitously set -- TEST FAILED");
      return 1;
    }

  puts ("Test succeeded.");
  return 0;
}
