/* Copyright (C) 1991, 1993, 1995, 1996 Free Software Foundation, Inc.
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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

/* Cause an abnormal program termination with core-dump.  */
void
abort (void)
{
  sigset_t sigs;

  if (__sigemptyset (&sigs) == 0 &&
      __sigaddset (&sigs, SIGABRT) == 0)
    __sigprocmask (SIG_UNBLOCK, &sigs, (sigset_t *) NULL);

  while (1)
    if (raise (SIGABRT))
      /* If we can't signal ourselves, exit.  */
      _exit (127);
  /* If we signal ourselves and are still alive,
     or can't exit, loop forever.  */
}
