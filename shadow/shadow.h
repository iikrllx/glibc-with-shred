/* Copyright (C) 1996 Free Software Foundation, Inc.
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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

/* Declaration of types and functions for shadow password suite.  */

#ifndef _SHADOW_H

#define _SHADOW_H	1
#include <features.h>

#define	__need_FILE
#include <stdio.h>

/* Paths to the userd files.  */
#define	SHADOW "/etc/shadow"


__BEGIN_DECLS

/* Structure of the password file.  */
struct spwd
{
  char *sp_namp;		/* Login name.  */
  char *sp_pwdp;		/* Encrypted password.  */
  long int sp_lstchg;		/* Date of last change.  */
  long int sp_min;		/* Minimum number of days between changes.  */
  long int sp_max;		/* Maximum number of days between changes.  */
  long int sp_warn;		/* Number of days to warn user to change
				   the password.  */
  long int sp_inact;		/* Number of days the account may be
				   inactive.  */
  long int sp_expire;		/* Number of days since 1970-01-01 until
				   account expires.  */
  unsigned long int sp_flag;	/* Reserved.  */
};


/* Open database for reading.  */
extern void setspent __P ((void));

/* Close database.  */
extern void endspent __P ((void));

/* Get next entry from database, perhaps after opening the file.  */
extern struct spwd *getspent __P ((void));

/* Get shadow entry matching NAME.  */
extern struct spwd *getspnam __P ((__const char *__name));

/* Read shadow entry from STRING.  */
extern struct spwd *sgetspent __P ((__const char *__string));

/* Read next shadow entry from STREAM.  */
extern struct spwd *fgetspent __P ((FILE *__stream));

/* Write line containing shadow password entry to stream.  */
extern int putspent __P ((__const struct spwd *__p, FILE *__stream));


#ifdef	__USE_REENTRANT
/* Reentrant versions of some of the functions above.  */
extern int __getspent_r __P ((struct spwd *__result_buf, char *__buffer,
			      size_t __buflen, struct spwd **__result));
extern int getspent_r __P ((struct spwd *__result_buf, char *__buffer,
			    size_t __buflen, struct spwd **__result));

extern int __getspnam_r __P ((__const char *__name, struct spwd *__result_buf,
			      char *__buffer, size_t __buflen,
			      struct spwd **__result));
extern int getspnam_r __P ((__const char *__name, struct spwd *__result_buf,
			    char *__buffer, size_t __buflen,
			    struct spwd **__result));

extern int __sgetspent_r __P ((__const char *__string,
			       struct spwd *__result_buf, char *__buffer,
			       size_t __buflen, struct spwd **__result));
extern int sgetspent_r __P ((__const char *__string, struct spwd *__result_buf,
			     char *__buffer, size_t __buflen,
			     struct spwd **__result));

extern int __fgetspent_r __P ((FILE *__stream, struct spwd *__result_buf,
			       char *__buffer, size_t __buflen,
			       struct spwd **__result));
extern int fgetspent_r __P ((FILE *__stream, struct spwd *__result_buf,
			     char *__buffer, size_t __buflen,
			     struct spwd **__result));
#endif	/* reentrant */


/* Protect password file against multi writers.  */
extern int __lckpwdf __P ((void));
extern int lckpwdf __P ((void));

/* Unlock password file.  */
extern int __ulckpwdf __P ((void));
extern int ulckpwdf __P ((void));

__END_DECLS

#endif /* shadow.h */
