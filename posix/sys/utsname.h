/* Copyright (C) 1991, 92, 94, 96, 97, 99 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/*
 *	POSIX Standard: 4.4 System Identification	<sys/utsname.h>
 */

#ifndef	_SYS_UTSNAME_H
#define	_SYS_UTSNAME_H	1

#include <features.h>

__BEGIN_DECLS

#include <bits/utsname.h>

#ifndef _UTSNAME_NODENAME_LENGTH
# define _UTSNAME_NODENAME_LENGTH _UTSNAME_LENGTH
#endif

/* Structure describing the system and machine.  */
struct utsname
  {
    /* Name of the implementation of the operating system.  */
    char sysname[_UTSNAME_LENGTH];

    /* Name of this node on the network.  */
    char nodename[_UTSNAME_NODENAME_LENGTH];

    /* Current release level of this implementation.  */
    char release[_UTSNAME_LENGTH];
    /* Current version level of this release.  */
    char version[_UTSNAME_LENGTH];

    /* Name of the hardware type the system is running on.  */
    char machine[_UTSNAME_LENGTH];

#if _UTSNAME_DOMAIN_LENGTH - 0
    /* Name of the domain of this node on the network.  */
# ifdef __USE_GNU
    char domainname[_UTSNAME_DOMAIN_LENGTH];
# else
    char __domainname[_UTSNAME_DOMAIN_LENGTH];
# endif
#endif
  };

#ifdef __USE_SVID
# define SYS_NMLN  _UTSNAME_LENGTH
#endif


/* Put information about the system in NAME.  */
extern int uname (struct utsname *__name) __THROW;


__END_DECLS

#endif /* sys/utsname.h  */
