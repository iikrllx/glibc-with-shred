/* Bounded-pointer symbol modifier.
   Copyright (C) 2000 Free Software Foundation, Inc.
   Contributed by Greg McGary <greg@mcgary.org>

   This file is part of the GNU C Library.  Its master source is NOT part of
   the C library, however.  The master source lives in the GNU MP Library.

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

#define BP_SYM(name) _BP_SYM (name)
#if __BOUNDED_POINTERS__
# define _BP_SYM(name) __BP_##name
#else
# define _BP_SYM(name) name
#endif
