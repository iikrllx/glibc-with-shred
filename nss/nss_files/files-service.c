/* Services file parser in nss_files module.
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

#include <netinet/in.h>
#include <netdb.h>


#define ENTNAME		servent
#define DATABASE	"services"

struct servent_data {};

#define TRAILING_LIST_MEMBER		s_aliases
#define TRAILING_LIST_SEPARATOR_P	isspace
#include "files-parse.c"
#define ISSLASH(c) ((c) == '/')
LINE_PARSER
("#",
 STRING_FIELD (result->s_name, isspace, 1);
 INT_FIELD (result->s_port, ISSLASH, 10, 0, htons);
 STRING_FIELD (result->s_proto, isspace, 1);
 )

#include GENERIC

DB_LOOKUP (servbyname, 1 + strlen (name), (".%s", name),
	   {
	     /* Must match both protocol and name.  */
	     if (strcmp (result->s_proto, proto))
	       continue;
	     LOOKUP_NAME (s_name, s_aliases)
	   },
	   const char *name, const char *proto)

DB_LOOKUP (servbyport, 20, ("=%d", port),
	   {
	     if (result->s_port == port)
	       break;
	   }, int port)
