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

#include <errno.h>
#include <stdio.h>


/* This returns a new stream opened on a temporary file (generated
   by tmpnam) The file is opened with mode "w+b" (binary read/write).
   If we couldn't generate a unique filename or the file couldn't
   be opened, NULL is returned.  */
FILE *
tmpfile64 ()
{
#ifdef _G_OPEN64
  char buf[FILENAME_MAX];
  char *filename;
  FILE *f;

  filename = __stdio_gen_tempname (buf, sizeof (buf), (char *) NULL, "tmpf", 0,
				   (size_t *) NULL, &f, 1);
  if (filename == NULL)
    return NULL;

  /* Note that this relies on the Unix semantics that
     a file is not really removed until it is closed.  */
  (void) remove (filename);

  return f;
#else
  __set_errno (ENOSYS);
  return NULL;
#endif
}
