/* Copyright (C) 1997, 2000, 2001 Free Software Foundation, Inc.
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

#ifndef _SYS_POLL_H
# error "Never use <bits/poll.h> directly; include <sys/poll.h> instead."
#endif

/* Event types that can be polled for.  These bits may be set in `events'
   to indicate the interesting event types; they will appear in `revents'
   to indicate the status of the file descriptor.  */
#define POLLIN		01              /* There is data to read.  */
#define POLLPRI		02              /* There is urgent data to read.  */
#define POLLOUT		04              /* Writing now will not block.  */

/* Some aliases.  */
#define POLLWRNORM	POLLOUT
#define POLLRDNORM	POLLIN
#define POLLRDBAND	POLLPRI

/* Event types always implicitly polled for.  These bits need not be set in
   `events', but they will appear in `revents' to indicate the status of
   the file descriptor.  */
#define POLLERR         010             /* Error condition.  */
#define POLLHUP         020             /* Hung up.  */
#define POLLNVAL        040             /* Invalid polling request.  */
