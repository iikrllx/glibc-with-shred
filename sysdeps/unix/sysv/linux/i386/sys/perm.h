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

#ifndef _SYS_PERM_H

#define _SYS_PERM_H	1
#include <features.h>

__BEGIN_DECLS

/* Set port input/output permissions.  */
extern int ioperm __P ((unsigned long __from, unsigned long __num,
			int __turn_on));


/* Change I/O privilege level.  */
extern int iopl __P ((int __level));

__END_DECLS

#endif	/* sys/perm.h */
