/* pthread_mutexattr_setprioceiling.  Hurd version.
   Copyright (C) 2016-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License
   as published by the Free Software Foundation; either
   version 2 of the license, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this program; if not, see
   <http://www.gnu.org/licenses/>.
*/

#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <pt-internal.h>
#include "pt-mutex.h"
#include <hurdlock.h>

int
pthread_mutexattr_setprioceiling (pthread_mutexattr_t *attrp, int cl)
{
  (void) attrp;
  (void) cl;
  return ENOSYS;
}

stub_warning (pthread_mutexattr_setprioceiling)
