/* Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Mark Kettenis <kettenis@phys.uva.nl>, 1997.

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

#ifndef	_UTMPX_H
#define	_UTMPX_H	1

#include <features.h>

__BEGIN_DECLS

/* Get system dependent values and data structures.  */
#include <bits/utmpx.h>

/* Open user accounting database.  */
extern void *setutxent __P ((void));

/* Close user accounting database.  */
extern void endutxent __P ((void));

/* Get the next entry from the user accounting database.  */
extern struct utmpx *getutxent __P ((void));

/* Get the user accounting database entry corresponding to ID.  */
extern struct utmpx *getutxid __P ((const struct utmpx *__id));

/* Get the user accounting database entry corresponding to LINE.  */
extern struct utmpx *getutxline __P ((const struct utmpx *__line));

/* Write the entry UTMPX into the user accounting database.  */
extern struct utmpx *pututxline __P ((const struct utmpx *__utmpx));

__END_DECLS

#endif /* utmpx.h  */
