/* Copyright (C) 1992, 1997 Free Software Foundation, Inc.
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

#include <mach.h>

/* These functions are called by MiG-generated code.  */

static mach_port_t reply_port;

/* Called by MiG to get a reply port.  */
mach_port_t
__mig_get_reply_port (void)
{
  if (reply_port == MACH_PORT_NULL)
    reply_port = __mach_reply_port ();

  return reply_port;
}

/* Called by MiG to deallocate the reply port.  */
void
__mig_dealloc_reply_port (void)
{
  mach_port_t port = reply_port;
  reply_port = MACH_PORT_NULL;	/* So the mod_refs RPC won't use it.  */
  __mach_port_mod_refs (__mach_task_self (), port,
			MACH_PORT_RIGHT_RECEIVE, -1);
}


/* Called at startup with CPROC == NULL.  cthreads has a different version
   of this function that is sometimes called with a `cproc_t' pointer.  */
void
__mig_init (void *cproc)
{
  if (cproc == 0)
    reply_port = MACH_PORT_NULL;
}
