/* Copyright (C) 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2009.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <gshadow.h>


#define LOOKUP_TYPE		struct sgrp
#define SETFUNC_NAME		setsgent
#define	GETFUNC_NAME		getsgent
#define	ENDFUNC_NAME		endsgent
#define DATABASE_NAME		gshadow
#define BUFLEN			1024
#define NO_COMPAT_NEEDED	1

#include "../nss/getXXent_r.c"
