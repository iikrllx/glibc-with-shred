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

#include <features.h>

/* We need to have the error status variable of the resolver
   accessible in the libc.  */
int __h_errno;
strong_alias (__h_errno, h_errno)

/* When threaded, h_errno may be a per-process variable.  */
#ifdef __USE_REENTRANT
int
weak_const_function
__h_errno_location (void)
{
  return &__h_errno;
}
#endif
