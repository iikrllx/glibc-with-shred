/* Copyright (C) 1991-99,2000,02 Free Software Foundation, Inc.
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

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <bits/libc-lock.h>
#include <nptl/pthreadP.h>
#include <tls.h>


#ifndef	HAVE_GNU_LD
#define	__environ	environ
#endif

#define	SHELL_PATH	"/bin/sh"	/* Path of the shell.  */
#define	SHELL_NAME	"sh"		/* Name to give it.  */


#ifdef _LIBC_REENTRANT
static struct sigaction intr, quit;
static int sa_refcntr;
__libc_lock_define_initialized (static, lock);

# define DO_LOCK() __libc_lock_lock (lock)
# define DO_UNLOCK() __libc_lock_unlock (lock)
# define INIT_LOCK() ({ __libc_lock_init (lock); sa_refcntr = 0; })
# define ADD_REF() sa_refcntr++
# define SUB_REF() --sa_refcntr
#else
# define DO_LOCK()
# define DO_UNLOCK()
# define INIT_LOCK()
# define ADD_REF() (void) 0
# define SUB_REF() 0
#endif


/* Execute LINE as a shell command, returning its status.  */
static int
do_system (const char *line)
{
  int status, save;
  pid_t pid;
  struct sigaction sa;
#ifndef _LIBC_REENTRANT
  struct sigaction intr, quit;
#endif
#ifndef WAITPID_CANNOT_BLOCK_SIGCHLD
  sigset_t block, omask;
#endif

  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  __sigemptyset (&sa.sa_mask);

  DO_LOCK ();
  if (ADD_REF () == 0)
    {
      if (__sigaction (SIGINT, &sa, &intr) < 0)
	{
	  SUB_REF ();
	  DO_UNLOCK ();
	  return -1;
	}
      if (__sigaction (SIGQUIT, &sa, &quit) < 0)
	{
	  save = errno;
	  goto out_restore_sigint;
	}
    }
  DO_UNLOCK ();

  __sigemptyset (&block);
  __sigaddset (&block, SIGCHLD);
  save = errno;
  if (__sigprocmask (SIG_BLOCK, &block, &omask) < 0)
    {
      if (errno == ENOSYS)
	__set_errno (save);
      else
	{
	  save = errno;
	  DO_LOCK ();
	  if (SUB_REF () == 0)
	    {
	      (void) __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL);
	out_restore_sigint:
	      (void) __sigaction (SIGINT, &intr, (struct sigaction *) NULL);
	    }
	  DO_UNLOCK ();
	  __set_errno (save);
	  return -1;
	}
    }

  pid = __fork ();
  if (pid == (pid_t) 0)
    {
      /* Child side.  */
      const char *new_argv[4];
      new_argv[0] = SHELL_NAME;
      new_argv[1] = "-c";
      new_argv[2] = line;
      new_argv[3] = NULL;

      /* Restore the signals.  */
      (void) __sigaction (SIGINT, &intr, (struct sigaction *) NULL);
      (void) __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL);
      (void) __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL);
      INIT_LOCK ();

      /* Exec the shell.  */
      (void) __execve (SHELL_PATH, (char *const *) new_argv, __environ);
      _exit (127);
    }
  else if (pid < (pid_t) 0)
    /* The fork failed.  */
    status = -1;
  else
    /* Parent side.  */
    {
#ifdef	NO_WAITPID
      pid_t child;
      do
	{
	  child = __wait (&status);
	  if (child <= -1 && errno != EINTR)
	    {
	      status = -1;
	      break;
	    }
	  /* Note that pid cannot be <= -1 and therefore the loop continues
	     when __wait returned with EINTR.  */
	}
      while (child != pid);
#else
      if (TEMP_FAILURE_RETRY (__waitpid (pid, &status, 0)) != pid)
	status = -1;
#endif
    }

  save = errno;
  DO_LOCK ();
  if ((SUB_REF () == 0
       && (__sigaction (SIGINT, &intr, (struct sigaction *) NULL)
	   | __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL)) != 0)
      || __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL) != 0)
    {
#ifndef _LIBC
      /* glibc cannot be used on systems without waitpid.  */
      if (errno == ENOSYS)
	__set_errno (save);
      else
#endif
	status = -1;
    }
  DO_UNLOCK ();

  return status;
}


int
__libc_system (const char *line)
{
  if (line == NULL)
    /* Check that we have a command processor available.  It might
       not be available after a chroot(), for example.  */
    return do_system ("exit 0") == 0;

#ifndef NOT_IN_libc
  if (__builtin_expect (THREAD_GETMEM (THREAD_SELF,
				       header.data.multiple_threads) == 0, 1))
    return do_system (line);

  /* XXX We have to install a cancellation handler to kill the child
     process.  */
  int oldtype = LIBC_CANCEL_ASYNC ();
#endif

  int result = do_system (line);

#ifndef NOT_IN_libc
  LIBC_CANCEL_RESET (oldtype);
#endif

  return result;
}
weak_alias (__libc_system, system)
