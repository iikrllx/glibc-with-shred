/* Initial program startup for running under the GNU Hurd.
Copyright (C) 1991, 1992, 1993, 1994, 1995 Free Software Foundation, Inc.
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <hurd.h>
#include <hurd/exec.h>
#include <sysdep.h>
#include <hurd/threadvar.h>
#include <unistd.h>
#include "set-hooks.h"
#include "hurdmalloc.h"		/* XXX */

mach_port_t *_hurd_init_dtable;
mach_msg_type_number_t _hurd_init_dtablesize;

unsigned int __hurd_threadvar_max;
unsigned long int __hurd_threadvar_stack_mask;
unsigned long int __hurd_threadvar_stack_offset;

/* These are set up by _hurdsig_init.  */
unsigned long int __hurd_sigthread_stack_base;
unsigned long int __hurd_sigthread_stack_end;
unsigned long int *__hurd_sigthread_variables;

vm_address_t _hurd_stack_base;
vm_size_t _hurd_stack_size;

/* Things that want to be run before _hurd_init or much anything else.
   Importantly, these are called before anything tries to use malloc.  */
DEFINE_HOOK (_hurd_preinit_hook, (void));

extern void __mach_init (void);
extern void __libc_init (int argc, char **argv, char **envp);

void *(*_cthread_init_routine) (void); /* Returns new SP to use.  */
void (*_cthread_exit_routine) (int status) __attribute__ ((__noreturn__));

int _hurd_split_args (char *, size_t, char **);

/* These communicate values from _hurd_startup to start1,
   where we cannot use the stack for anything.  */
struct info
  {
    char *args, *env;
    mach_port_t *portarray;
    int *intarray;
    mach_msg_type_number_t argslen, envlen, portarraysize, intarraysize;
    int flags;
    char **argv, **envp;
    int argc;
    void (*hurd_main) (int, char **, char **,
		       mach_port_t *, mach_msg_type_number_t,
		       int *, mach_msg_type_number_t);
  };

static void start1 (struct info *) __attribute__ ((__noreturn__));


/* Entry point.  This is the first thing in the text segment.

   The exec server started the initial thread in our task with this spot the
   PC, and a stack that is presumably big enough.  We do basic Mach
   initialization so mig-generated stubs work, and then do an exec_startup
   RPC on our bootstrap port, to which the exec server responds with the
   information passed in the exec call, as well as our original bootstrap
   port, and the base address and size of the preallocated stack.

   If using cthreads, we are given a new stack by cthreads initialization and
   deallocate the stack set up by the exec server.  On the new stack we call
   `start1' (above) to do the rest of the startup work.  Since the stack may
   disappear out from under us in a machine-dependent way, we use a pile of
   static variables to communicate the information from exec_startup to start1.
   This is unfortunate but preferable to machine-dependent frobnication to copy
   the state from the old stack to the new one.  */

void
_hurd_startup (void **argptr,
	       void (*main) (int, char **, char **,
			     mach_port_t *, mach_msg_type_number_t,
			     int *, mach_msg_type_number_t))
{
  error_t err;
  mach_port_t in_bootstrap;
  struct info i;

  /* Basic Mach initialization, must be done before RPCs can be done.  */
  __mach_init ();

  /* Run things that want to do initialization as soon as possible.  We do
     this before exec_startup so that no out of line data arrives and
     clutters up the address space before brk initialization.  */

  RUN_HOOK (_hurd_preinit_hook, ());

  if (err = __task_get_special_port (__mach_task_self (), TASK_BOOTSTRAP_PORT,
				     &in_bootstrap))
    LOSE;

  if (in_bootstrap != MACH_PORT_NULL)
    {
      /* Call the exec server on our bootstrap port and
	 get all our standard information from it.  */

      i.argslen = i.envlen = 0;
      _hurd_init_dtablesize = i.portarraysize = i.intarraysize = 0;

      err = __exec_startup (in_bootstrap,
			    &_hurd_stack_base, &_hurd_stack_size,
			    &i.flags,
			    &i.args, &i.argslen, &i.env, &i.envlen,
			    &_hurd_init_dtable, &_hurd_init_dtablesize,
			    &i.portarray, &i.portarraysize,
			    &i.intarray, &i.intarraysize);
      __mach_port_deallocate (__mach_task_self (), in_bootstrap);
    }

  if (err || in_bootstrap == MACH_PORT_NULL)
    {
      /* Either we have no bootstrap port, or the RPC to the exec server
	 failed.  Try to snarf the args in the canonical Mach way.
	 Hopefully either they will be on the stack as expected, or the
	 stack will be zeros so we don't crash.  Set all our other
	 variables to have empty information.  */

      /* SNARF_ARGS (ARGPTR, ARGC, ARGV, ENVP) snarfs the arguments and
	 environment from the stack, assuming they were put there by the
	 microkernel.  */
      SNARF_ARGS (argptr, i.argc, i.argv, i.envp);

      i.flags = 0;
      i.args = i.env = NULL;
      i.argslen = i.envlen = 0;
      _hurd_init_dtable = NULL;
      _hurd_init_dtablesize = 0;
      i.portarray = NULL;
      i.portarraysize = 0;
      i.intarray = NULL;
      i.intarraysize = 0;
    }
  else
    i.argv = i.envp = NULL;

  i.hurd_main = main;

  /* The user might have defined a value for this, to get more variables.
     Otherwise it will be zero on startup.  We must make sure it is set
     properly before before cthreads initialization, so cthreads can know
     how much space to leave for thread variables.  */
  if (__hurd_threadvar_max < _HURD_THREADVAR_MAX)
    __hurd_threadvar_max = _HURD_THREADVAR_MAX;

  /* Do cthreads initialization and switch to the cthread stack.  */

  if (_cthread_init_routine != NULL)
    CALL_WITH_SP (start1, i, (*_cthread_init_routine) ());
  else
    start1 (&i);

  /* Should never get here.  */
  LOSE;
}


static void
start1 (struct info *info)
{
  register int envc = 0;

  {
    /* Check if the stack we are now on is different from
       the one described by _hurd_stack_{base,size}.  */

    char dummy;
    const vm_address_t newsp = (vm_address_t) &dummy;

    if (_hurd_stack_size != 0 && (newsp < _hurd_stack_base ||
				  newsp - _hurd_stack_base > _hurd_stack_size))
      /* The new stack pointer does not intersect with the
	 stack the exec server set up for us, so free that stack.  */
      __vm_deallocate (__mach_task_self (),
		       _hurd_stack_base, _hurd_stack_size);
  }

  if (__hurd_threadvar_stack_mask == 0)
    {
      /* We are not using cthreads, so we will have just a single allocated
	 area for the per-thread variables of the main user thread.  */
      unsigned long int i;
      __hurd_threadvar_stack_offset
	= (unsigned long int) malloc (__hurd_threadvar_max *
				      sizeof (unsigned long int));
      if (__hurd_threadvar_stack_offset == 0)
	__libc_fatal ("Can't allocate single-threaded per-thread variables.");
      for (i = 0; i < __hurd_threadvar_max; ++i)
	((unsigned long int *) __hurd_threadvar_stack_offset)[i] = 0;
    }


  /* Turn the block of null-separated strings we were passed for the
     arguments and environment into vectors of pointers to strings.  */

  if (! info->argv)
    {
      if (info->args)
	/* Count up the arguments so we can allocate ARGV.  */
	info->argc = _hurd_split_args (args, argslen, NULL);
      if (! info->args || info->argc == 0)
	{
	  /* No arguments passed; set argv to { NULL }.  */
	  info->argc = 0;
	  info->args = NULL;
	  info->argv = (char **) &info->args;
	}
    }

  if (! info->envp)
    {
      if (info->env)
	/* Count up the environment variables so we can allocate ENVP.  */
	envc = _hurd_split_args (info->env, info->envlen, NULL);
      if (! info->env || envc == 0)
	{
	  /* No environment passed; set __environ to { NULL }.  */
	  info->env = NULL;
	  info->envp = (char **) &env;
	}
    }

  if (! info->argv)
    {
      /* There were some arguments.
	 Allocate space for the vectors of pointers and fill them in.  */
      info->argv = __alloca ((info->argc + 1) * sizeof (char *));
      _hurd_split_args (info->args, info->argslen, info->argv);
    }
  
  if (! info->envp)
    {
      /* There was some environment.
	 Allocate space for the vectors of pointers and fill them in.  */
      info->envp = __alloca ((envc + 1) * sizeof (char *));
      _hurd_split_args (info->env, info->envlen, info->envp);
    }

  (*info->hurd_main) (info->argc, info->argv, info->envp,
		      info->portarray, info->portarraysize,
		      info->intarray, info->intarraysize);

  /* Should never get here.  */
  LOSE;
}

/* Split ARGSLEN bytes at ARGS into words, breaking at NUL characters.  If
   ARGV is not a null pointer, store a pointer to the start of each word in
   ARGV[n], and null-terminate ARGV.  Return the number of words split.  */

int
_hurd_split_args (char *args, size_t argslen, char **argv)
{
  char *p = args;
  size_t n = argslen;
  int argc = 0;

  while (n > 0)
    {
      char *end = memchr (p, '\0', n);

      if (argv)
	argv[argc] = p;
      ++argc;

      if (end == NULL)
	/* The last argument is unterminated.  */
	break;

      n -= end + 1 - p;
      p = end + 1;
    }

  if (argv)
    argv[argc] = NULL;
  return argc;
}
