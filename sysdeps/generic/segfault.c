/* Catch segmentation faults and print backtrace.
   Copyright (C) 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#include <ctype.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* This file defines macros to access the content of the sigcontext element
   passed up by the signal handler.  */
#include <sigcontextinfo.h>

/* Get code to possibly dump the content of all registers.  */
#include <register-dump.h>

/* This is a global variable set at program start time.  It marks the
   highest used stack address.  */
extern void *__libc_stack_end;


/* This implementation assumes a stack layout that matches the defaults
   used by gcc's `__builtin_frame_address' and `__builtin_return_address'
   (FP is the frame pointer register):

	  +-----------------+     +-----------------+
    FP -> | previous FP --------> | previous FP ------>...
	  |                 |     |                 |
	  | return address  |     | return address  |
	  +-----------------+     +-----------------+

  */

/* Get some notion of the current stack.  Need not be exactly the top
   of the stack, just something somewhere in the current frame.  */
#ifndef CURRENT_STACK_FRAME
# define CURRENT_STACK_FRAME  ({ char __csf; &__csf; })
#endif

/* By default we assume that the stack grows downward.  */
#ifndef INNER_THAN
# define INNER_THAN <
#endif

struct layout
{
  struct layout *next;
  void *return_address;
};


/* This function is called when a segmentation fault is caught.  The system
   is in an instable state now.  This means especially that malloc() might
   not work anymore.  */
static void
catch_segfault (int signal, SIGCONTEXT ctx)
{
  struct layout *current;
  void *top_frame;
  void *top_stack;
  const char *fname;
  int fd;
  void **arr;
  size_t cnt;
  struct sigaction sa;
  const char *sigstring;

  /* This is the name of the file we are writing to.  If none is given
     or we cannot write to this file write to stderr.  */
  fd = 2;
  fname = getenv ("SEGFAULT_OUTPUT_NAME");
  if (fname != NULL && fname[0] != '\0')
    {
      fd = open (fname, O_TRUNC | O_WRONLY | O_CREAT, 0666);
      if (fd == -1)
	fd = 2;
    }

#define WRITE_STRING(s) write (fd, s, strlen (s))
  WRITE_STRING ("*** ");
  sigstring = strsignal (signal);
  WRITE_STRING (sigstring);
  WRITE_STRING ("\n");

#ifdef REGISTER_DUMP
  REGISTER_DUMP;
#endif

  WRITE_STRING ("\nBacktrace:\n");

  top_frame = GET_FRAME (ctx);
  top_stack = GET_STACK (ctx);

  /* First count how many entries we'll have.  */
  cnt = 1;
  current = (struct layout *) top_frame;
  while (!((void *) current INNER_THAN top_stack
	   || !((void *) current INNER_THAN __libc_stack_end)))
    {
      ++cnt;

      current = current->next;
    }

  arr = alloca (cnt * sizeof (void *));

  /* First handle the program counter from the structure.  */
  arr[0] = GET_PC (ctx);

  current = (struct layout *) top_frame;
  cnt = 1;
  while (!((void *) current INNER_THAN top_stack
	   || !((void *) current INNER_THAN __libc_stack_end)))
    {
      arr[cnt++] = current->return_address;

      current = current->next;
    }

  /* If the last return address was NULL, assume that it doesn't count.  */
  if (arr[cnt-1] == NULL)
    cnt--;

  /* Now generate nicely formatted output.  */
  __backtrace_symbols_fd (arr, cnt, fd);

  /* Pass on the signal (so that a core file is produced).  */
  sa.sa_handler = SIG_DFL;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (signal, &sa, NULL);
  raise (signal);
}


static void
__attribute__ ((constructor))
install_handler (void)
{
  struct sigaction sa;
  const char *sigs = getenv ("SEGFAULT_SIGNALS");

  sa.sa_handler = (void *) catch_segfault;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigs == NULL)
    sigaction (SIGSEGV, &sa, NULL);
  else if (sigs[0] == '\0')
    /* Do not do anything.  */
    return;
  else
    {
      const char *where;
      int all = __strcasecmp (sigs, "all");

#define INSTALL_FOR_SIG(sig, name) \
      where = __strcasestr (sigs, name);				      \
      if (all || (where != NULL						      \
		  && (where == sigs || !isalnum (where[-1]))		      \
		  && !isalnum (where[sizeof (name) - 1])))		      \
	sigaction (sig, &sa, NULL);

      INSTALL_FOR_SIG (SIGSEGV, "segv");
      INSTALL_FOR_SIG (SIGILL, "ill");
#ifdef SIGBUS
      INSTALL_FOR_SIG (SIGBUS, "bus");
#endif
#ifdef SIGSTKFLT
      INSTALL_FOR_SIG (SIGSTKFLT, "stkflt");
#endif
      INSTALL_FOR_SIG (SIGABRT, "abrt");
      INSTALL_FOR_SIG (SIGFPE, "fpe");
    }

  /* Maybe we are expected to use an alternative stack.  */
  if (getenv ("SEGFAULT_USE_ALTSTACK") != 0)
    {
      void *stack_mem = malloc (2 * SIGSTKSZ);
      struct sigaltstack ss;

      if (stack_mem != NULL)
	{
	  ss.ss_sp = stack_mem;
	  ss.ss_flags = SS_ONSTACK;
	  ss.ss_size = 2 * SIGSTKSZ;

	  sigaltstack (&ss, NULL);
	}
    }
}
