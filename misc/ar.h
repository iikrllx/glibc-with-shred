/* Header describing `ar' archive file format.
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

#ifndef _AR_H
#define _AR_H 1

/* Archive files start with the ARMAG identifying string.  Then follows a
   `struct ar_hdr', and as many bytes of member file data as its `ar_size'
   member indicates, for each member file.  */

#define ARMAG	"!<arch>\n"	/* String that begins an archive file.  */
#define SARMAG	8		/* Size of that string.  */

#define ARFMAG	"`\n"		/* String in ar_fmag at end of each header.  */

struct ar_hdr
  {
    char ar_name[16];		/* Member file name, sometimes / terminated. */
    char ar_date[12];		/* File date, decimal seconds since Epoch.  */
    char ar_uid[6], ar_gid[6];	/* User and group IDs, in ASCII decimal.  */
    char ar_mode[8];		/* File mode, in ASCII octal.  */
    char ar_size[10];		/* File size, in ASCII decimal.  */
    char ar_fmag[2];		/* Always contains ARFMAG.  */
  };

#endif /* ar.h */
