/* Copyright (C) 1996, 1997 Free Software Foundation, Inc.
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

#include <ctype.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>

/* Define a line parsing function using the common code
   used in the nss_files module.  */

#define STRUCTURE	spwd
#define ENTNAME		spent
struct spent_data {};

/* Predicate which always returns false, needed below.  */
#define FALSE(arg) 0


#include "../nss/nss_files/files-parse.c"
LINE_PARSER
(,
 STRING_FIELD (result->sp_namp, ISCOLON, 0);
 if (line[0] == '\0'
     && (result->sp_namp[0] == '+' || result->sp_namp[0] == '-'))
   {
     result->sp_pwdp = NULL;
     result->sp_lstchg = 0;
     result->sp_min = 0;
     result->sp_max = 0;
     result->sp_warn = -1l;
     result->sp_inact = -1l;
     result->sp_expire = -1l;
     result->sp_flag = ~0ul;
   }
 else
   {
     STRING_FIELD (result->sp_pwdp, ISCOLON, 0);
     INT_FIELD_MAYBE_NULL (result->sp_lstchg, ISCOLON, 0, 10, (long int),
			   (long int) -1);
     INT_FIELD_MAYBE_NULL (result->sp_min, ISCOLON, 0, 10, (long int),
			   (long int) -1);
     INT_FIELD_MAYBE_NULL (result->sp_max, ISCOLON, 0, 10, (long int),
			   (long int -1);
     while (isspace (*line))
       ++line;
     if (*line == '\0')
       {
	 /* The old form.  */
	 result->sp_warn = -1l;
	 result->sp_inact = -1l;
	 result->sp_expire = -1l;
	 result->sp_flag = ~0ul;
       }
     else
       {
	 INT_FIELD_MAYBE_NULL (result->sp_warn, ISCOLON, 0, 10, (long int),
			       (long int) -1);
	 INT_FIELD_MAYBE_NULL (result->sp_inact, ISCOLON, 0, 10, (long int),
			       (long int) -1);
	 INT_FIELD_MAYBE_NULL (result->sp_expire, ISCOLON, 0, 10, (long int),
			       (long int) -1);
	 if (*line != '\0')
	   INT_FIELD_MAYBE_NULL (result->sp_flag, FALSE, 0, 10,
				 (unsigned long int), ~0ul)
	 else
	   result->sp_flag = ~0ul;
       }
   }
 )


/* Read one shadow entry from the given stream.  */
int
__sgetspent_r (const char *string, struct spwd *resbuf, char *buffer,
	       size_t buflen, struct spwd **result)
{
  *result = parse_line (strncpy (buffer, string, buflen), resbuf, NULL, 0)
    ? resbuf : NULL;

  return *result == NULL ? errno : 0;
}
weak_alias (__sgetspent_r, sgetspent_r)
