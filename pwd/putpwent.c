/* Copyright (C) 1991, 1992, 1996, 1997, 1998 Free Software Foundation, Inc.
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
#include <pwd.h>

#define _S(x)	x ? x : ""

/* Write an entry to the given stream.
   This must know the format of the password file.  */
int
putpwent (p, stream)
     const struct passwd *p;
     FILE *stream;
{
  if (p == NULL || stream == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (fprintf (stream, "%s:%s:%u:%u:%s:%s:%s\n",
	       p->pw_name, _S (p->pw_passwd),
	       p->pw_uid, p->pw_gid,
	       _S (p->pw_gecos), _S (p->pw_dir), _S (p->pw_shell)) < 0)
    return -1;

  return 0;
}
