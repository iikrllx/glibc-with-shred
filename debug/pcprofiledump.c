/* Dump information generated by PC profiling.
   Copyright (C) 1999, 2002, 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1999.

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

/* This is mainly an example.  It shows how programs which want to use
   the information should read the file.  */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <argp.h>
#include <byteswap.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../version.h"

#define PACKAGE _libc_intl_domainname

#ifndef _
# define _(Str) gettext (Str)
#endif

#ifndef N_
# define N_(Str) Str
#endif

/* Definitions of arguments for argp functions.  */
static const struct argp_option options[] =
{
  { "unbuffered", 'u', NULL, 0, N_("Don't buffer output") },
  { NULL, 0, NULL, 0, NULL }
};

/* Short description of program.  */
static const char doc[] = N_("Dump information generated by PC profiling.");

/* Strings for arguments in help texts.  */
static const char args_doc[] = N_("[FILE]");

/* Function to print some extra text in the help message.  */
static char *more_help (int key, const char *text, void *input);

/* Prototype for option handler.  */
static error_t parse_opt (int key, char *arg, struct argp_state *state);

/* Data structure to communicate with argp functions.  */
static struct argp argp =
{
  options, parse_opt, args_doc, doc, NULL, more_help
};


int
main (int argc, char *argv[])
{
  /* Set locale via LC_ALL.  */
  setlocale (LC_ALL, "");

  /* Set the text message domain.  */
  textdomain (PACKAGE);

  /* Parse and process arguments.  */
  int remaining;
  argp_parse (&argp, argc, argv, 0, &remaining, NULL);

  int fd;
  if (remaining == argc)
    fd = STDIN_FILENO;
  else if (remaining + 1 != argc)
    {
      argp_help (&argp, stdout, ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR,
		 program_invocation_short_name);
      exit (1);
    }
  else
    {
      /* Open the given file.  */
      fd = open (argv[remaining], O_RDONLY);

      if (fd == -1)
	error (EXIT_FAILURE, errno, _("cannot open input file"));
    }

  /* Read the first 4-byte word.  It contains the information about
     the word size and the endianess.  */
  uint32_t word;
  if (TEMP_FAILURE_RETRY (read (fd, &word, 4)) != 4)
    error (EXIT_FAILURE, errno, _("cannot read header"));

  /* Check whether we have to swap the byte order.  */
  int must_swap = (word & 0xfffffff0) == bswap_32 (0xdeb00000);
  if (must_swap)
    word = bswap_32 (word);

  /* We have two loops, one for 32 bit pointers, one for 64 bit pointers.  */
  if (word == 0xdeb00004)
    {
      union
      {
	uint32_t ptrs[2];
	char bytes[8];
      } pair;

      while (1)
	{
	  size_t len = sizeof (pair);
	  size_t n;

	  while (len > 0
		 && (n = TEMP_FAILURE_RETRY (read (fd, &pair.bytes[8 - len],
						   len))) != 0)
	    len -= n;

	  if (len != 0)
	    /* Nothing to read.  */
	    break;

	  printf ("this = %#010" PRIx32 ", caller = %#010" PRIx32 "\n",
		  must_swap ? bswap_32 (pair.ptrs[0]) : pair.ptrs[0],
		  must_swap ? bswap_32 (pair.ptrs[1]) : pair.ptrs[1]);
	}
    }
  else if (word == 0xdeb00008)
    {
      union
      {
	uint64_t ptrs[2];
	char bytes[16];
      } pair;

      while (1)
	{
	  size_t len = sizeof (pair);
	  size_t n;

	  while (len > 0
		 && (n = TEMP_FAILURE_RETRY (read (fd, &pair.bytes[8 - len],
						   len))) != 0)
	    len -= n;

	  if (len != 0)
	    /* Nothing to read.  */
	    break;

	  printf ("this = %#018" PRIx64 ", caller = %#018" PRIx64 "\n",
		  must_swap ? bswap_64 (pair.ptrs[0]) : pair.ptrs[0],
		  must_swap ? bswap_64 (pair.ptrs[1]) : pair.ptrs[1]);
	}
    }
  else
    /* This should not happen.  */
    error (EXIT_FAILURE, 0, _("invalid pointer size"));

  /* Clean up.  */
  close (fd);

  return 0;
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'u':
      setbuf (stdout, NULL);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static char *
more_help (int key, const char *text, void *input)
{
  switch (key)
    {
    case ARGP_KEY_HELP_EXTRA:
      /* We print some extra information.  */
      return strdup (gettext ("\
For bug reporting instructions, please see:\n\
<http://www.gnu.org/software/libc/bugs.html>.\n"));
    default:
      break;
    }
  return (char *) text;
}
