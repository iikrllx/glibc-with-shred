/* Initialization code run first thing by the ELF startup code.  Linux version.
   Copyright (C) 1995-1999, 2000 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sysdep.h>
#include <fpu_control.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include "kernel-features.h"

extern void __libc_init_secure (void);
extern void __libc_init (int, char **, char **);
extern void __libc_global_ctors (void);

/* The function is called from assembly stubs the compiler can't see.  */
static void init (int, char **, char **) __attribute__ ((unused));

/* The function we use to get the kernel revision.  */
extern int __sysctl (int *name, int nlen, void *oldval, size_t *oldlenp,
		     void *newval, size_t newlen);

extern int _dl_starting_up;
weak_extern (_dl_starting_up)

extern fpu_control_t _dl_fpu_control;
extern int _dl_fpu_control_set;

/* Set nonzero if we have to be prepared for more then one libc being
   used in the process.  Safe assumption if initializer never runs.  */
int __libc_multiple_libcs = 1;

/* Remember the command line argument and enviroment contents for
   later calls of initializers for dynamic libraries.  */
int __libc_argc;
char **__libc_argv;


static void
init (int argc, char **argv, char **envp)
{
  extern void __getopt_clean_environment (char **);

  /* Make sure we don't initialize twice.  */
  if (!__libc_multiple_libcs)
    {
      /* Test whether the kernel is new enough.  This test is only
         performed if the library is not compiled to run on all
         kernels.  */
      if (__LINUX_KERNEL_VERSION > 0)
	{
	  static const int sysctl_args[] = { CTL_KERN, KERN_OSRELEASE };
	  char buf[64];
	  size_t reslen = sizeof (buf);
	  unsigned int version;
	  int parts;
	  char *cp;

	  /* Try reading the number using `sysctl' first.  */
	  if (__sysctl ((int *) sysctl_args,
			sizeof (sysctl_args) / sizeof (sysctl_args[0]),
			buf, &reslen, NULL, 0) < 0)
	    {
	      /* This was not successful.  Now try reading the /proc
		 filesystem.  */
	      int fd = __open ("/proc/sys/kernel/osrelease", O_RDONLY);
	      if (fd == -1
		  || (reslen = __read (fd, buf, sizeof (buf))) <= 0)
		/* This also didn't work.  We give up since we cannot
		   make sure the library can actually work.  */
		__libc_fatal ("FATAL: cannot determine library version\n");

	      __close (fd);
	    }
	  buf[MIN (reslen, sizeof (buf) - 1)] = '\0';

	  /* Now convert it into a number.  The string consists of at most
	     three parts.  */
	  version = 0;
	  parts = 0;
	  cp = buf;
	  while ((*cp >= '0') && (*cp <= '9'))
	    {
	      unsigned int here = *cp++ - '0';

	      while ((*cp >= '0') && (*cp <= '9'))
		{
		  here *= 10;
		  here += *cp++ - '0';
		}

	      ++parts;
	      version <<= 8;
	      version |= here;

	      if (*cp++ != '.')
		/* Another part following?  */
		break;
	    }

	  if (parts < 3)
	    version <<= 8 * (3 - parts);

	  /* Now we can test with the required version.  */
	  if (version < __LINUX_KERNEL_VERSION)
	    /* Not sufficent.  */
	    __libc_fatal ("FATAL: kernel too old\n");
	}

      /* Set the FPU control word to the proper default value if the
	 kernel would use a different value.  (In a static program we
	 don't have this information.)  */
#ifdef SHARED
      if (__fpu_control != _dl_fpu_control)
#endif
	__setfpucw (__fpu_control);
    }

  /* Save the command-line arguments.  */
  __libc_argc = argc;
  __libc_argv = argv;
  __environ = envp;

#ifndef SHARED
  __libc_init_secure ();
#endif

  __libc_init (argc, argv, envp);

  /* This is a hack to make the special getopt in GNU libc working.  */
  __getopt_clean_environment (envp);

#ifdef SHARED
  __libc_global_ctors ();
#endif
}

#ifdef SHARED

strong_alias (init, _init);

void
__libc_init_first (void)
{
}

#else
void
__libc_init_first (int argc, char **argv, char **envp)
{
  init (argc, argv, envp);
}
#endif


/* This function is defined here so that if this file ever gets into
   ld.so we will get a link error.  Having this file silently included
   in ld.so causes disaster, because the _init definition above will
   cause ld.so to gain an init function, which is not a cool thing. */

void
_dl_start (void)
{
  abort ();
}
