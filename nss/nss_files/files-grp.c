/* Group file parser in nss_files module.
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

#include <grp.h>

#define STRUCTURE	group
#define ENTNAME		grent
#define DATAFILE	"/etc/group"
struct grent_data {};

#define TRAILING_LIST_MEMBER		gr_mem
#define TRAILING_LIST_SEPARATOR_P(c)	((c) == ',')
#include "files-parse.c"
/* Our parser function is already defined in fgetgrent.c, so use that.
   to parse lines from the database file.  */
extern int parse_line (char *line, struct STRUCTURE *result,
		       void *buffer, int buflen);

#include "files-XXX.c"

DB_LOOKUP (grnam,
	   {
	     if (! strcmp (name, result->gr_name))
	       break;
	   }, const char *name)

DB_LOOKUP (grgid,
	   {
	     if (result->gr_gid == gid)
	       break;
	   }, gid_t gid)
