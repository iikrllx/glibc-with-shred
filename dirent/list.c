/* Copyright (C) 1991, 1993, 1997, 1998, 2000 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>


static int
test (const char *name)
{
  DIR *dirp;
  struct dirent *entp;
  int retval = 0;

  puts (name);

  dirp = opendir (name);
  if (dirp == NULL)
    {
      perror ("opendir");
      return 1;
    }

  errno = 0;
  while ((entp = readdir (dirp)) != NULL)
    printf ("%s\tfile number %lu\n",
	    entp->d_name, (unsigned long int) entp->d_fileno);

  if (errno)
    {
      perror ("readdir");
      retval = 1;
    }

  if (closedir (dirp) < 0)
    {
      perror ("closedir");
      retval = 1;
    }

  return retval;
}

int
main (int argc, char **argv)
{
  int retval = 0;
  --argc;
  ++argv;

  if (argc == 0)
    retval = test (".");
  else
    while (argc-- > 0)
      retval |= test (*argv++);

  return retval;
}
