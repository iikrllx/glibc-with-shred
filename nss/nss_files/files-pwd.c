/* User file parser in nss_files module.
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
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <pwd.h>

#define STRUCTURE	passwd
#define ENTNAME		pwent
#define DATABASE	"passwd"
struct pwent_data {};

/* Our parser function is already defined in fgetpwent_r.c, so use that
   to parse lines from the database file.  */
#define EXTERN_PARSER
#include "files-parse.c"
#include GENERIC

DB_LOOKUP (pwnam, 1 + strlen (name), (".%s", name),
	   {
	     if (name[0] != '+' && name[0] != '-'
		 && ! strcmp (name, result->pw_name))
	       break;
	   }, const char *name)

DB_LOOKUP (pwuid, 20, ("=%lu", (unsigned long int) uid),
	   {
	     if (result->pw_uid == uid && result->pw_name[0] != '+'
		 && result->pw_name[0] != '-')
	       break;
	   }, uid_t uid)
