/* Perform a `longjmp' on a Mach thread_state.  Stub version.
Copyright (C) 1991, 1994 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <setjmp.h>
#include <mach/thread_status.h>

/* Set up STATE to do the equivalent of `longjmp (ENV, VAL);'.  */

void
_hurd_longjmp_thread_state (void *state, jmp_buf env, int val)
{
  /* Set all the registers in *STATE to the values described by ENV and
     RETVAL.  After this, setting that thread's state to STATE should be
     just like calling `longjmp (ENV, RETVAL)'.  */
  #error "Need to write sysdeps/mach/hurd/MACHINE/longjmp-ctx.c"
}
