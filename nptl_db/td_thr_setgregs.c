/* Set a thread's general register set.
   Copyright (C) 1999, 2001, 2002, 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 1999.

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

#include "thread_dbP.h"


td_err_e
td_thr_setgregs (const td_thrhandle_t *th, prgregset_t gregs)
{
  LOG ("td_thr_setgregs");

  /* We have to get the state and the PID for this thread.  */
  int cancelhandling;
  if (ps_pdread (th->th_ta_p->ph,
		 &((struct pthread *) th->th_unique)->cancelhandling,
		 &cancelhandling, sizeof (int)) != PS_OK)
    return TD_ERR;

  /* Only set the registers if the thread hasn't yet terminated.  */
  if ((cancelhandling & TERMINATED_BITMASK) == 0)
    {
      pid_t tid;

      if (ps_pdread (th->th_ta_p->ph,
		     &((struct pthread *) th->th_unique)->tid,
		     &tid, sizeof (pid_t)) != PS_OK
	  || ps_lsetregs (th->th_ta_p->ph, tid, gregs) != PS_OK)
	return TD_ERR;
    }

  return TD_OK;
}
