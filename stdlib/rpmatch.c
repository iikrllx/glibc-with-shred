/* rpmatch - determine whether string value is affirmation or negative
	     response according to current locale's data
Copyright (C) 1996 Free Software Foundation, Inc.

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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <langinfo.h>
#include <stdlib.h>
#include <regex.h>


int
rpmatch (response)
     const char *response;
{
  /* Match against one of the response patterns, compiling the pattern
     first if necessary.  */
  inline int try (const int tag, const int match, const int nomatch,
		  const char **lastp, regex_t *re)
    {
      const char *pattern = nl_langinfo (tag);
      if (pattern != *lastp)
	{
	  /* The pattern has changed.  */
	  if (*lastp)
	    {
	      /* Free the old compiled pattern.  */
	      regfree (re);
	      *lastp = NULL;
	    }
	  /* Compile the pattern and cache it for future runs.  */
	  if (regcomp (re, pattern, REG_EXTENDED) != 0)
	    return -1;
	  *lastp = pattern;
	}

      /* Try the pattern.  */
      return regexec (re, response, 0, NULL, 0) == 0 ? match : nomatch;
    }

  /* We cache the response patterns and compiled regexps here.  */
  static const char *yesexpr, *noexpr;
  static regex_t yesre, nore;

  return (try (YESEXPR, 1, 0, &yesexpr, &yesre) ?:
	  try (NOEXPR, 0, -1, &noexpr, &nore));
}
