/* POSIX.1 `sigaction' call for Linux/i386.
   Copyright (C) 1991, 1995, 1996, 1997 Free Software Foundation, Inc.
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

#include <sysdep.h>
#include <errno.h>
#include <stddef.h>
#include <signal.h>

/* The difference here is that the sigaction structure used in the
   kernel is not the same as we use in the libc.  Therefore we must
   translate it here.  */
#include <kernel_sigaction.h>


/* If ACT is not NULL, change the action for SIG to *ACT.
   If OACT is not NULL, put the old action for SIG in *OACT.  */
int
__sigaction (int sig, const struct sigaction *act, struct sigaction *oact)
{
  struct kernel_sigaction k_newact, k_oldact;
  int result;

  if (act)
    {
      k_newact.sa_handler = act->sa_handler;
      k_newact.sa_mask = act->sa_mask.__val[0];
      k_newact.sa_flags = act->sa_flags;

      k_newact.sa_restorer = ((act->sa_flags & SA_NOMASK)
			      ? &&restore_nomask : &&restore);
    }

  asm volatile ("pushl %%ebx\n"
		"movl %2, %%ebx\n"
		"int $0x80\n"
		"popl %%ebx"
		: "=a" (result)
		: "0" (SYS_ify (sigaction)), "r" (sig),
		  "c" (act ? &k_newact : 0), "d" (oact ? &k_oldact : 0));

  if (result < 0)
    {
      __set_errno (-result);
      return -1;
    }

  if (oact)
    {
      oact->sa_handler = k_oldact.sa_handler;
      oact->sa_mask.__val[0] = k_oldact.sa_mask;
      oact->sa_flags = k_oldact.sa_flags;
      oact->sa_restorer = k_oldact.sa_restorer;
    }

  return 0;

 restore:
  asm (
#ifdef	PIC
       "	pushl %%ebx\n"
       "	call 0f\n"
       "0:	popl %%ebx\n"
       "	addl $_GLOBAL_OFFSET_TABLE_+[.-0b], %%ebx\n"
       "	addl $8, %%esp\n"
       "	call __sigsetmask@PLT\n"
       "	addl $8, %%esp\n"
       "	popl %%ebx\n"
#else
       "	addl $4, %%esp\n"
       "	call __sigsetmask\n"
       "	addl $4, %%esp\n"
#endif
       "	popl %%eax\n"
       "	popl %%ecx\n"
       "	popl %%edx\n"
       "	popf\n"
       "	ret"
       : : );

 restore_nomask:
  asm ("	addl $4, %%esp\n"
       "	popl %%eax\n"
       "	popl %%ecx\n"
       "	popl %%edx\n"
       "	popf\n"
       "	ret"
       : : );

  /* NOTREACHED */
  return -1;
}

weak_alias (__sigaction, sigaction)
