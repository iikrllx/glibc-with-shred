/* Copyright (C) 2002-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

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
   <https://www.gnu.org/licenses/>.  */

#include "pthreadP.h"
#include <libc-lock.h>

void
_pthread_cleanup_push_defer (struct _pthread_cleanup_buffer *buffer,
			     void (*routine) (void *), void *arg)
{
  buffer->__routine = routine;
  buffer->__arg = arg;
  __libc_cleanup_push_defer (buffer);
}
strong_alias (_pthread_cleanup_push_defer, __pthread_cleanup_push_defer)


void
_pthread_cleanup_pop_restore (struct _pthread_cleanup_buffer *buffer,
			      int execute)
{
  __libc_cleanup_pop_restore (buffer);

  /* If necessary call the cleanup routine after we removed the
     current cleanup block from the list.  */
  if (execute)
    buffer->__routine (buffer->__arg);
}
strong_alias (_pthread_cleanup_pop_restore, __pthread_cleanup_pop_restore)
