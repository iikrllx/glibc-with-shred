/* `sln' program to create symbolic links between files.
   Copyright (C) 1998, 1999, 2001 Free Software Foundation, Inc.
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

#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#if !defined S_ISDIR && defined S_IFDIR
#define	S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

static int makesymlink (const char *src, const char *dest);
static int makesymlinks (const char *file);

int
main (int argc, char **argv)
{
  switch (argc)
    {
    case 2:
      return makesymlinks (argv [1]);
      break;

    case 3:
      return makesymlink (argv [1], argv [2]);
      break;

    default:
      printf ("Usage: %s src dest|file\n", argv [0]);
      return 1;
      break;
    }
}

static int
makesymlinks (file)
     const char *file;
{
#ifndef PATH_MAX
#define PATH_MAX 4095
#endif
  char *buffer = NULL;
  size_t bufferlen = 0;
  int ret;
  int lineno;
  FILE *fp;

  if (strcmp (file, "-") == 0)
    fp = stdin;
  else
    {
      fp = fopen (file, "r");
      if (fp == NULL)
	{
	  fprintf (stderr, "%s: file open error: %m\n", file);
	  return 1;
	}
    }

  ret = 0;
  lineno = 0;
  while (!feof_unlocked (fp))
    {
      ssize_t n = getline (&buffer, &bufferlen, fp);
      char *src;
      char *dest;
      char *cp = buffer;

      if (n < 0)
	break;
      if (buffer[n - 1] == '\n')
	buffer[n - 1] = '\0';

      ++lineno;
      while (isspace (*cp))
	++cp;
      if (*cp == '\0')
	/* Ignore empty lines.  */
	continue;
      src = cp;

      do
	++cp;
      while (*cp != '\0' && ! isspace (*cp));
      if (*cp != '\0')
	*cp++ = '\0';

      while (isspace (*cp))
	++cp;
      if (*cp == '\0')
	{
	  fprintf (stderr, "No target in line %d\n", lineno);
	  ret = 1;
	  continue;
	}
      dest = cp;

      do
	++cp;
      while (*cp != '\0' && ! isspace (*cp));
      if (*cp != '\0')
	*cp++ = '\0';

      ret |= makesymlink (src, dest);
    }
  fclose (fp);

  return ret;
}

static int
makesymlink (src, dest)
     const char *src;
     const char *dest;
{
  struct stat stats;
  const char *error;

  /* Destination must not be a directory. */
  if (lstat (dest, &stats) == 0)
    {
      if (S_ISDIR (stats.st_mode))
	{
	  fprintf (stderr, "%s: destination must not be a directory\n",
	  	   dest);
	  return 1;
	}
      else if (unlink (dest) && errno != ENOENT)
	{
	  fprintf (stderr, "%s: failed to remove the old destination\n",
	  	   dest);
	  return 1;
	}
    }
  else if (errno != ENOENT)
    {
      error = strerror (errno);
      fprintf (stderr, "%s: invalid destination: %s\n", dest, error);
      return -1;
    }

#ifdef S_ISLNK
  if (symlink (src, dest) == 0)
#else
  if (link (src, dest) == 0)
#endif
    {
      /* Destination must exist by now. */
      if (access (dest, F_OK))
        {
	  error = strerror (errno);
	  unlink (dest);
	  fprintf (stderr, "Invalid link from \"%s\" to \"%s\": %s\n",
	  	   src, dest, error);
	  return 1;
	}
      return 0;
    }
  else
    {
      error = strerror (errno);
      fprintf (stderr, "Invalid link from \"%s\" to \"%s\": %s\n",
      	       src, dest, error);
      return 1;
    }
}
