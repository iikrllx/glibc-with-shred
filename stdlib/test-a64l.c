/* Test program for the l64a and a64l functions.
   Copyright (C) 2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Schwab <schwab@suse.de>.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prototype for our test function.  */
extern int do_test (int argc, char *argv[]);
#include <test-skeleton.c>

struct a64l_test
{
  const char *base64;
  long int value;
};

static const struct a64l_test tests[] =
  {
    { "./", 64 },
    { "", 0 },
    { "/", 1 },
    { "FT", 2001 },
    { NULL, 0 }
  };

int
do_test (int argc, char ** argv)
{
  const struct a64l_test *at;
  long int l;
  const char *s;
  int status = 0;

  for (at = tests; at->base64 != NULL; ++at)
    {
      printf ("a64l (\"%s\")", at->base64);
      l = a64l (at->base64);
      if (l == at->value)
	puts ("\tOK");
      else
	{
	  printf ("\tBAD\n  returns %ld, expected %ld\n", l, at->value);
	  status = 1;
	}
      printf ("l64a (%ld)", at->value);
      s = l64a (at->value);
      if (strcmp (s, at->base64) == 0)
	puts ("\tOK");
      else
	{
	  printf ("\tBAD\n  returns \"%s\", expected \"%s\"\n", s, at->base64);
	  status = 1;
	}
    }

  return status ? EXIT_FAILURE : EXIT_SUCCESS;
}
