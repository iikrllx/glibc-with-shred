/* Notify initiator of AIO request.
   Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <pthread.h>
#include <stdlib.h>
#include "aio_misc.h"

int
__aio_notify_only (struct sigevent *sigev)
{
  int result = 0;

  /* Send the signal to notify about finished processing of the request.  */
  if (sigev->sigev_notify == SIGEV_THREAD)
    {
      /* We have to start a thread.  */
      pthread_t tid;
      pthread_attr_t attr, *pattr;

      pattr = (pthread_attr_t *) sigev->sigev_notify_attributes;
      if (pattr == NULL)
	{
	  pthread_attr_init (&attr);
	  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
	  pattr = &attr;
	}

      if (pthread_create (&tid, pattr,
			  (void *(*) (void *)) sigev->sigev_notify_function,
			  sigev->sigev_value.sival_ptr) < 0)
	result = -1;
    }
  else if (sigev->sigev_notify == SIGEV_SIGNAL)
    /* We have to send a signal.  */
    if (__aio_sigqueue (sigev->sigev_signo, sigev->sigev_value) < 0)
      result = -1;

  return result;
}


void
__aio_notify (struct requestlist *req)
{
  struct waitlist *waitlist;
  struct aiocb *aiocbp = &req->aiocbp->aiocb;

  if (__aio_notify_only (&aiocbp->aio_sigevent) != 0)
    {
      /* XXX What shall we do if already an error is set by
	 read/write/fsync?  */
      aiocbp->__error_code = errno;
      aiocbp->__return_value = -1;
    }

  /* Now also notify possibly waiting threads.  */
  waitlist = req->waiting;
  while (waitlist != NULL)
    {
      struct waitlist *next = waitlist->next;

      /* Decrement the counter.  This is used in both cases.  */
      --*waitlist->counterp;

      if (waitlist->sigevp == NULL)
	pthread_cond_signal (waitlist->cond);
      else
	/* This is part of a asynchronous `lio_listio' operation.  If
	   this request is the last one, send the signal.  */
	if (*waitlist->counterp == 0)
	  {
	    __aio_notify_only (waitlist->sigevp);
	    /* This is tricky.  See lio_listio.c for the reason why
	       this works.  */
	    free ((void *) waitlist->counterp);
	  }

      waitlist = next;
    }
}
