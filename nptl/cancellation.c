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

#include <setjmp.h>
#include <stdlib.h>
#include "pthreadP.h"


/* This function is responsible for calling all registered cleanup
   handlers and then terminate the thread.  This includes dellocating
   the thread-specific data.  The implementation is complicated by the
   fact that we have to handle to cancellation handler registration
   methods: exceptions using try/finally and setjmp.

   The setjmp method is always available.  The user might compile some
   code which uses this method because no modern compiler is
   available.  So we have to handle these first since we cannot call
   the cleanup handlers if the stack frames are gone.  At the same
   time this opens a hole for the register exception handler blocks
   since now they might be in danger of using an overwritten stack
   frame.  The advise is to only use new or only old style cancellation
   handling.  */
void
__do_cancel (char *currentframe)
{
  struct pthread *self = THREAD_SELF;

  /* Cleanup the thread-local storage.  */
  __cleanup_thread (self, currentframe);

  /* Throw an exception.  */
  // XXX TBI

  /* If throwing an exception didn't work try the longjmp.  */
  __libc_longjmp (self->cancelbuf, 1);

  /* NOTREACHED */
}


void
__cleanup_thread (struct pthread *self, char *currentframe)
{
  struct _pthread_cleanup_buffer *cleanups;

  /* Call all registered cleanup handlers.  */
  cleanups = THREAD_GETMEM (self, cleanup);
  if (__builtin_expect (cleanups != NULL, 0))
    {
      struct _pthread_cleanup_buffer *last;

      while (FRAME_LEFT (currentframe, cleanups))
	{
	  last = cleanups;
	  cleanups = cleanups->__prev;

	  if (cleanups == NULL || FRAME_LEFT (last, cleanups))
	    {
	      cleanups = NULL;
	      break;
	    }
	}

      while (cleanups != NULL)
	{
	  /* Call the registered cleanup function.  */
	  cleanups->__routine (cleanups->__arg);

	  last = cleanups;
	  cleanups = cleanups->__prev;

	  if (FRAME_LEFT (last, cleanups))
	    break;
	}
    }
}
