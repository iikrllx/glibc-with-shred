/* pthread_attr_getschedparam.  Generic version.
   Copyright (C) 2002-2020 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library;  if not, see
   <https://www.gnu.org/licenses/>.  */

#include <pthread.h>
#include <sched.h>
#include <string.h>

#include <pt-internal.h>

int
__pthread_attr_getschedparam (const pthread_attr_t *attr,
			      struct sched_param *param)
{
  memcpy (param, &attr->__schedparam, sizeof *param);
  return 0;
}

strong_alias (__pthread_attr_getschedparam, pthread_attr_getschedparam);
