/* Copyright (C) 2004 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <errno.h>
#include <mqueue.h>
#include <sysdep.h>

#ifdef __NR_mq_getsetattr

/* Query status and attributes of message queue MQDES.  */
int
mq_getattr (mqd_t mqdes, struct mq_attr *mqstat)
{
  return mq_setattr (mqdes, NULL, mqstat);
}

#else
# include <sysdeps/generic/mq_getattr.c>
#endif
