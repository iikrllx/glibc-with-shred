/* Copyright (C) 2010-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Maxim Kuvyrkov <maxim@codesourcery.com>, 2010.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _SEMAPHORE_H
# error "Never use <bits/semaphore.h> directly; include <semaphore.h> instead."
#endif


#define __SIZEOF_SEM_T	16


/* Value returned if `sem_open' failed.  */
#define SEM_FAILED      ((sem_t *) 0)


typedef union
{
  char __size[__SIZEOF_SEM_T];
  long int __align __attribute__ ((__aligned__ (4)));
} sem_t;
