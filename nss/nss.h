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

/* Define interface to NSS.  This is meant for the interface functions
   and for implementors of new services.  */

#ifndef _NSS_H

#define _NSS_H	1
#include <features.h>

/* Revision number of NSS interface (must be a string).  */
#define NSS_SHLIB_REVISION __nss_shlib_revision
extern const char *const __nss_shlib_revision;


__BEGIN_DECLS

/* Possible results of lookup using a nss_* function.  */
enum nss_status
{
  NSS_STATUS_TRYAGAIN = -2,
  NSS_STATUS_UNAVAIL,
  NSS_STATUS_NOTFOUND,
  NSS_STATUS_SUCCESS,
  NSS_STATUS_RETURN
};


/* Overwrite service selection for database DBNAME using specification
   in STRING.
   This function should only be used by system programs which have to
   work around non-existing services (e.e., while booting).
   Attention: Using this function repeatedly will slowly eat up the
   whole memory since previous selection data cannot be freed.  */
extern int __nss_configure_lookup __P ((__const char *__dbname,
					__const char *__string));

__END_DECLS

#endif /* nss.h */
