/* Copyright (C) 2001 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>

extern void fluffy (void *p);
extern void bar (void *p);

int global;

void
fluffy (void *p)
{
  printf ("This is %s\n", __FUNCTION__);
  *(int *) p = global = 1;
}


void
bar (void *p)
{
  extern void *__dso_handle;
  printf ("This is %s\n", __FUNCTION__);
  __cxa_atexit (fluffy, p, __dso_handle);
}
