/* Copyright (C) 1991, 1993, 1996, 1997 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <string.h>


/* Generate a unique filename in P_tmpdir.  If S is NULL return NULL.
   This makes this function thread safe.  */
char *
tmpnam_r (char *s)
{
  if (s == NULL)
    return NULL;

  /* In the following call we use the buffer pointed to by S if
     non-NULL although we don't know the size.  But we limit the size
     to L_tmpnam characters in any case.  */
  return __stdio_gen_tempname (s, L_tmpnam, (const char *) NULL,
			       (const char *) NULL, 0,
			       (size_t *) NULL, (FILE **) NULL, 0);
}
