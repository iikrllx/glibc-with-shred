/* Copyright (C) 2002 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <unistd.h>
#include <list.h>
#include "fork.h"
#include <dl-sysdep.h>
#include <tls.h>
#include <string.h>
#include <pthreadP.h>
#include <bits/libc-lock.h>


static struct fork_handler pthread_child_handler;


void
__libc_pthread_init (ptr, reclaim, functions)
     unsigned long int *ptr;
     void (*reclaim) (void);
     const struct pthread_functions *functions;
{
  /* Remember the pointer to the generation counter in libpthread.  */
  __fork_generation_pointer = ptr;

  /* Called by a child after fork.  */
  pthread_child_handler.handler = reclaim;

  /* The fork handler needed by libpthread.  */
  list_add_tail (&pthread_child_handler.list, &__fork_child_list);

#ifdef SHARED
  /* We copy the content of the variable pointed to by the FUNCTIONS
     parameter to one in libc.so since this means access to the array
     can be done with one memory access instead of two.  */
  memcpy (&__libc_pthread_functions, functions,
	  sizeof (__libc_pthread_functions));
#endif
}
