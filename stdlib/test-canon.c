/* Test program for returning the canonical absolute name of a given file.
Copyright (C) 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by David Mosberger <davidm@azstarnet.com>.

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

/* This file must be run from within a directory called "stdlib".  */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

static char	cwd[1024];
static size_t	cwd_len;

struct {
  const char *	name;
  const char *	value;
} symlinks[] = {
  {"SYMLINK_LOOP",	"SYMLINK_LOOP"},
  {"SYMLINK_1",		"."},
  {"SYMLINK_2",		"//////./../../etc"},
  {"SYMLINK_3",		"SYMLINK_1"},
  {"SYMLINK_4",		"SYMLINK_2"},
  {"SYMLINK_5",		"doesNotExist"},
};

struct {
  const char * in, * out, * resolved;
  int error;
} tests[] = {
  /*  0 */
  {"/",					"/"},
  {"/////////////////////////////////",	"/"},
  {"/.././.././.././..///",		"/"},
  {"/etc",				"/etc"},
  {"/etc/../etc",		 	"/etc"},
  /*  5 */
  {"/doesNotExist/../etc",		0, "/doesNotExist", ENOENT},
  {"./././././././././.",		"."},
  {"/etc/.//doesNotExist",		0, "/etc/doesNotExist", ENOENT},
  {"./doesExist",			"./doesExist"},
  {"./doesExist/",			"./doesExist"},
  /* 10 */
  {"./doesExist/../doesExist",		"./doesExist"},
  {"foobar",				0, "./foobar", ENOENT},
  {".",					"."},
  {"./foobar",				0, "./foobar", ENOENT},
  {"SYMLINK_LOOP",			0, "./SYMLINK_LOOP", ELOOP},
  /* 15 */
  {"./SYMLINK_LOOP",			0, "./SYMLINK_LOOP", ELOOP},
  {"SYMLINK_1",				"."},
  {"SYMLINK_1/foobar",			0, "./foobar", ENOENT},
  {"SYMLINK_2",				"/etc"},
  {"SYMLINK_3",				"."},
  /* 20 */
  {"SYMLINK_4",				"/etc"},
  {"../stdlib/SYMLINK_1",		"."},
  {"../stdlib/SYMLINK_2",		"/etc"},
  {"../stdlib/SYMLINK_3",		"."},
  {"../stdlib/SYMLINK_4",		"/etc"},
  /* 25 */
  {"./SYMLINK_5",			0, "./doesNotExist", ENOENT},
  {"SYMLINK_5",				0, "./doesNotExist", ENOENT},
  {"SYMLINK_5/foobar",			0, "./doesNotExist", ENOENT},
  {"doesExist/../../stdlib/doesExist",	"./doesExist"},
  {"doesExist/.././../stdlib/.",	"."}
};


int
check_path (const char * result, const char * expected)
{
  int good;

  if (!result)
    return (expected == NULL);

  if (!expected)
    return 0;

  if (expected[0] == '.' && (expected[1] == '/' || expected[1] == '\0'))
    good = (strncmp (result, cwd, cwd_len) == 0
	    && strcmp (result + cwd_len, expected + 1) == 0);
  else
    good = (strcmp (expected, result) == 0);

  return good;
}


void
main (int argc, char ** argv)
{
  char * result;
  int fd, i, errors = 0;
  char buf[PATH_MAX];

  getcwd (cwd, sizeof(buf));
  cwd_len = strlen (cwd);

  for (i = 0; i < sizeof (symlinks) / sizeof (symlinks[0]); ++i)
    symlink (symlinks[i].value, symlinks[i].name);

  fd = open("doesExist", O_CREAT | O_EXCL, 0777);

  for (i = 0; i < sizeof (tests) / sizeof (tests[0]); ++i)
    {
      buf[0] = '\0';
      result = realpath (tests[i].in, buf);

      if (!check_path (result, tests[i].out))
	{
	  printf ("%s: flunked test %d (expected `%s', got `%s')\n",
		  argv[0], i, tests[i].out ? tests[i].out : "NULL",
		  result ? result : "NULL");
	  ++errors;
	  continue;
	}

      if (!check_path (buf, tests[i].out ? tests[i].out : tests[i].resolved))
	{
	  printf ("%s: flunked test %d (expected resolved `%s', got `%s')\n",
		  argv[0], i, tests[i].out ? tests[i].out : tests[i].resolved,
		  buf);
	  ++errors;
	  continue;
	}

      if (!tests[i].out && errno != tests[i].error)
	{
	  printf ("%s: flunked test %d (expected errno %d, got %d)\n",
		  argv[0], i, tests[i].errno, errno);
	  ++errors;
	  continue;
	}
    }

  getcwd (buf, sizeof(buf));
  if (strcmp (buf, cwd))
    {
      printf ("%s: current working directory changed from %s to %s\n",
	      argv[0], cwd, buf);
      ++errors;
    }

  if (fd >= 0)
    unlink("doesExist");

  for (i = 0; i < sizeof (symlinks) / sizeof (symlinks[0]); ++i)
    unlink (symlinks[i].name);

  if (errors == 0)
    {
      puts ("No errors.");
      exit (EXIT_SUCCESS);
    }
  else
    {
      printf ("%d errors.\n", errors);
      exit (EXIT_FAILURE);
    }
}
