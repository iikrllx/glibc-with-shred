/* The `struct utmp' type, describing entries in the utmp file.  Generic/BSDish
Copyright (C) 1993, 1996 Free Software Foundation, Inc.

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

#ifndef _UTMPBITS_H

#define _UTMPBITS_H	1
#include <features.h>

#include <time.h>

#define	_PATH_UTMP	"/var/run/utmp"
#define	_PATH_WTMP	"/var/log/wtmp"
#define	_PATH_LASTLOG	"/var/log/lastlog"

#define	UT_NAMESIZE	8
#define	UT_LINESIZE	8
#define	UT_HOSTSIZE	16

__BEGIN_DECLS

struct lastlog {
	time_t	ll_time;
	char	ll_line[UT_LINESIZE];
	char	ll_host[UT_HOSTSIZE];
};

struct utmp {
	char	ut_line[UT_LINESIZE];
	char	ut_name[UT_NAMESIZE];
	char	ut_host[UT_HOSTSIZE];
	long	ut_time;
};

__END_DECLS

#endif /* utmpbits.h */

