/* Initialization code run first thing by the ELF startup code.  For i386/Hurd.
Copyright (C) 1995 Free Software Foundation, Inc.
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

#include <hurd.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "hurdstartup.h"
#include "set-hooks.h"
#include "hurdmalloc.h"		/* XXX */

extern void __mach_init (void);
extern void __libc_init (int, char **, char **);

void *(*_cthread_init_routine) (void); /* Returns new SP to use.  */
void (*_cthread_exit_routine) (int status) __attribute__ ((__noreturn__));


/* Things that want to be run before _hurd_init or much anything else.
   Importantly, these are called before anything tries to use malloc.  */
DEFINE_HOOK (_hurd_preinit_hook, (void));


static void
init1 (int argc, char *arg0, ...)
{
  char **argv = &arg0;
  char **envp = &argv[argc + 1];
  struct hurd_startup_data *d;

  __environ = envp;
  while (*envp)
    ++envp;
  d = (void *) ++envp;

  /* If we are the bootstrap task started by the kernel,
     then after the environment pointers there is no Hurd
     data block; the argument strings start there.  */
  if ((void *) d != argv[0])
    {
      _hurd_init_dtable = d->dtable;
      _hurd_init_dtablesize = d->dtablesize;

      {
	/* Check if the stack we are now on is different from
	   the one described by _hurd_stack_{base,size}.  */

	char dummy;
	const vm_address_t newsp = (vm_address_t) &dummy;

	if (d->stack_size != 0 && (newsp < d->stack_base ||
				   newsp - d->stack_base > d->stack_size))
	  /* The new stack pointer does not intersect with the
	     stack the exec server set up for us, so free that stack.  */
	  __vm_deallocate (__mach_task_self (), d->stack_base, d->stack_size);
      }
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

  if ((void *) d != argv[0] && (d->portarray || d->intarray))
    /* Initialize library data structures, start signal processing, etc.  */
    _hurd_init (d->flags, argv,
		d->portarray, d->portarraysize,
		d->intarray, d->intarraysize);

  __libc_init (argc, argv, __environ);
}

static void
init (int *data, void *usercode, void **retaddrloc)
{
  int argc = *data;
  char **argv = (void *) (data + 1);
  char **envp = &argv[argc + 1];
  struct hurd_startup_data *d;

  __environ = envp;
  while (*envp)
    ++envp;
  d = (void *) ++envp;

  /* The user might have defined a value for this, to get more variables.
     Otherwise it will be zero on startup.  We must make sure it is set
     properly before before cthreads initialization, so cthreads can know
     how much space to leave for thread variables.  */
  if (__hurd_threadvar_max < _HURD_THREADVAR_MAX)
    __hurd_threadvar_max = _HURD_THREADVAR_MAX;


  /* After possibly switching stacks, call `init1' (above) with the user
     code as the return address, and the argument data immediately above
     that on the stack.  */

  if (_cthread_init_routine)
    {
      /* Initialize cthreads, which will allocate us a new stack to run on.  */
      void *newsp = (*_cthread_init_routine) ();
      struct hurd_startup_data *od;

      /* Copy the argdata from the old stack to the new one.  */
      newsp = memcpy (newsp - ((char *) &d[1] - (char *) data), data,
		      (char *) d - (char *) data);

      /* Set up the Hurd startup data block immediately following
	 the argument and environment pointers on the new stack.  */
      od = (newsp + ((char *) d - (char *) data));
      if ((void *) argv[0] == d)
	/* We were started up by the kernel with arguments on the stack.
	   There is no Hurd startup data, so zero the block.  */
	memset (od, 0, sizeof *od);
      else
	/* Copy the Hurd startup data block to the new stack.  */
	*od = *d;

      /* Push the user code address on the top of the new stack.  It will
	 be the return address for `init1'; we will jump there with NEWSP
	 as the stack pointer.  */
      *--(void **) newsp = usercode;
      /* Mutate our own return address to run the code below.  */
      *retaddrloc = &&switch_stacks;
      /* Force NEWSP into %ecx and &init1 into %eax, which are not restored
         by function return.  */
      asm volatile ("# a %0 c %1" : : "a" (&init1), "c" (newsp));
      return;
    switch_stacks:
      /* Our return address was redirected to here, so at this point our
	 stack is unwound and callers' registers restored.  Only %ecx and
	 %eax are call-clobbered and thus still have the values we set just
	 above.  Fetch from there the new stack pointer we will run on, and
	 jmp to the run-time address of `init1'; when it returns, it will
	 run the user code with the argument data at the top of the stack.  */
      asm volatile ("movl %ecx, %esp; jmp *%eax");
      /* NOTREACHED */
    }
  else
    {
      /* We are not switching stacks, but we must play some games with
	 the one we've got, similar to the stack-switching code above.  */
      *retaddrloc = &&call_init1;
      /* Force the user code address into %ecx and the run-time address of
	 `init1' into %eax, for use below.  */
      asm volatile ("# a %0 c %1" : : "a" (&init1), "c" (usercode));
      return;
    call_init1:
      /* As in the stack-switching case, at this point our stack is unwound
	 and callers' registers restored, and only %ecx and %eax
	 communicate values from the lines above.  In this case we have
	 stashed in %ecx the user code return address.  Push it on the top
	 of the stack so it acts as init1's return address, and then jump
	 there.  */
      asm volatile ("pushl %ecx; jmp *%eax");
      /* NOTREACHED */
    }
}  


#ifdef PIC
/* This function is called to initialize the shared C library.
   It is called just before the user _start code from i386/elf/start.S,
   with the stack set up as that code gets it.  */

/* NOTE!  The linker notices the magical name `_init' and sets the DT_INIT
   pointer in the dynamic section based solely on that.  It is convention
   for this function to be in the `.init' section, but the symbol name is
   the only thing that really matters!!  */
/*void _init (int argc, ...) __attribute__ ((unused, section (".init")));*/

void
_init (int argc, ...)
{
  /* Initialize data structures so we can do RPCs.  */
  __mach_init ();

  RUN_HOOK (_hurd_preinit_hook, ());
  
  init (&argc, ((void **) &argc)[-1], &((void **) &argc)[-1]);
}
#endif


void
__libc_init_first (int argc __attribute__ ((unused)), ...)
{
#ifndef PIC
  void doinit (int *data)
    {
      init (data, ((void **) &argc)[-1], &((void **) &data)[-1]);
    }

  /* Initialize data structures so we can do RPCs.  */
  __mach_init ();

  RUN_HOOK (_hurd_preinit_hook, ());
  
  _hurd_startup ((void **) &argc, &doinit);
#endif
}
