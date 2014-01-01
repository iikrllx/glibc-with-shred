/* Copyright (C) 2009-2014 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <libintl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <not-cancel.h>


#define MF(l) MF1 (l)
#define MF1(l) str_##l
#define C(s1, s2) C1 (s1, s2)
#define C1(s1, s2) s1##s2

#define NOW SIGILL
#include "psiginfo-define.h"

#define NOW SIGFPE
#include "psiginfo-define.h"

#define NOW SIGSEGV
#include "psiginfo-define.h"

#define NOW SIGBUS
#include "psiginfo-define.h"

#define NOW SIGTRAP
#include "psiginfo-define.h"

#define NOW SIGCLD
#include "psiginfo-define.h"

#define NOW SIGPOLL
#include "psiginfo-define.h"


/* Print out on stderr a line consisting of the test in S, a colon, a space,
   a message describing the meaning of the signal number PINFO and a newline.
   If S is NULL or "", the colon and space are omitted.  */
void
psiginfo (const siginfo_t *pinfo, const char *s)
{
  char buf[512];
  FILE *fp = fmemopen (buf, sizeof (buf), "w");
  if (fp == NULL)
    {
      const char *colon;

      if (s == NULL || *s == '\0')
	s = colon = "";
      else
	colon = ": ";

      __fxprintf (NULL, "%s%ssignal %d\n", s, colon, pinfo->si_signo);
      return;
    }

  if (s != NULL && *s != '\0')
    fprintf (fp, "%s: ", s);

  const char *desc;
  if (pinfo->si_signo >= 0 && pinfo->si_signo < NSIG
      && ((desc = _sys_siglist[pinfo->si_signo]) != NULL
#ifdef SIGRTMIN
	  || (pinfo->si_signo >= SIGRTMIN && pinfo->si_signo < SIGRTMAX)
#endif
	 ))
    {
#ifdef SIGRTMIN
      if (desc == NULL)
	{
	  if (pinfo->si_signo - SIGRTMIN < SIGRTMAX - pinfo->si_signo)
	    {
	      if (pinfo->si_signo == SIGRTMIN)
		fprintf (fp, "SIGRTMIN (");
	      else
		fprintf (fp, "SIGRTMIN+%d (", pinfo->si_signo - SIGRTMIN);
	    }
	  else
	    {
	      if (pinfo->si_signo == SIGRTMAX)
		fprintf (fp, "SIGRTMAX (");
	      else
		fprintf (fp, "SIGRTMAX-%d (", SIGRTMAX - pinfo->si_signo);
	    }
	}
      else
#endif
	fprintf (fp, "%s (", _(desc));

      const char *base = NULL;
      const uint8_t *offarr = NULL;
      size_t offarr_len = 0;
      switch (pinfo->si_signo)
	{
#define H(sig) \
	case sig:							      \
	  base = C(codestrs_, sig).str;					      \
	  offarr = C (codes_, sig);					      \
	  offarr_len = sizeof (C (codes_, sig)) / sizeof (C (codes_, sig)[0]);\
	  break

	  H (SIGILL);
	  H (SIGFPE);
	  H (SIGSEGV);
	  H (SIGBUS);
	  H (SIGTRAP);
	  H (SIGCHLD);
	  H (SIGPOLL);
	}

      const char *str = NULL;
      if (offarr != NULL
	  && pinfo->si_code >= 1 && pinfo->si_code <= offarr_len)
	str = base + offarr[pinfo->si_code - 1];
      else
	switch (pinfo->si_code)
	  {
	  case SI_USER:
	    str = N_("Signal sent by kill()");
	    break;
	  case SI_QUEUE:
	    str = N_("Signal sent by sigqueue()");
	    break;
	  case SI_TIMER:
	    str = N_("Signal generated by the expiration of a timer");
	    break;
	  case SI_ASYNCIO:
	    str = N_("\
Signal generated by the completion of an asynchronous I/O request");
	    break;
	  case SI_MESGQ:
	    str = N_("\
Signal generated by the arrival of a message on an empty message queue");
	    break;
#ifdef SI_TKILL
	  case SI_TKILL:
	    str = N_("Signal sent by tkill()");
	    break;
#endif
#ifdef SI_ASYNCNL
	  case SI_ASYNCNL:
	    str = N_("\
Signal generated by the completion of an asynchronous name lookup request");
	    break;
#endif
#ifdef SI_SIGIO
	  case SI_SIGIO:
	    str = N_("\
Signal generated by the completion of an I/O request");
	    break;
#endif
#ifdef SI_KERNEL
	  case SI_KERNEL:
	    str = N_("Signal sent by the kernel");
	    break;
#endif
	  }

      if (str != NULL)
	fprintf (fp, "%s ", _(str));
      else
	fprintf (fp, "%d ", pinfo->si_code);

      if (pinfo->si_signo == SIGILL || pinfo->si_signo == SIGFPE
	  || pinfo->si_signo == SIGSEGV || pinfo->si_signo == SIGBUS)
	fprintf (fp, "[%p])\n", pinfo->si_addr);
      else if (pinfo->si_signo == SIGCHLD)
	fprintf (fp, "%ld %d %ld)\n",
		 (long int) pinfo->si_pid, pinfo->si_status,
		 (long int) pinfo->si_uid);
      else if (pinfo->si_signo == SIGPOLL)
	fprintf (fp, "%ld)\n", (long int) pinfo->si_band);
      else
	fprintf (fp, "%ld %ld)\n",
		 (long int) pinfo->si_pid, (long int) pinfo->si_uid);
    }
  else
    fprintf (fp, _("Unknown signal %d\n"),  pinfo->si_signo);

  fclose (fp);

  write_not_cancel (STDERR_FILENO, buf, strlen (buf));
}
