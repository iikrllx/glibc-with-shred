/* Copyright (C) 1991 Free Software Foundation, Inc.
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

#include <ansidecl.h>
#include <errno.h>
#include <string.h>


static char *olds = NULL;

/* Parse S into tokens separated by characters in DELIM.
   If S is NULL, the last string strtok() was called with is
   used.  For example:
	char s[] = "-abc=-def";
	x = strtok(s, "-");		// x = "abc"
	x = strtok(NULL, "=-");		// x = "def"
	x = strtok(NULL, "=");		// x = NULL
		// s = "abc\0-def\0"
*/
char *
DEFUN(strtok, (s, delim),
      register char *s AND register CONST char *delim)
{
  char *token;

  if (s == NULL)
    {
      if (olds == NULL)
	{
	  errno = EINVAL;
	  return NULL;
	}
      else
	s = olds;
    }

  /* Scan leading delimiters.  */
  s += strspn(s, delim);
  if (*s == '\0')
    {
      olds = NULL;
      return NULL;
    }

  /* Find the end of the token.  */
  token = s;
  s = strpbrk(token, delim);
  if (s == NULL)
    /* This token finishes the string.  */
    olds = NULL;
  else
    {
      /* Terminate the token and make OLDS point past it.  */
      *s = '\0';
      olds = s + 1;
    }
  return token;
}
