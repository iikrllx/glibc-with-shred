/* Copyright (C) 2000, 2001 Free Software Foundation, Inc.
   Contributed by Martin Schwidefsky (schwidefsky@de.ibm.com).
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

#include <signal.h>

#define SIGCONTEXT struct sigcontext *
#define SIGCONTEXT_EXTRA_ARGS
#define GET_PC(ctx)	((void *)((ctx)->sregs->regs.psw.addr))
#define GET_FRAME(ctx)	(*(void **)((ctx)->sregs->regs.gprs[11]))
#define GET_STACK(ctx)	((void *)((ctx)->sregs->regs.gprs[15]))
#define CALL_SIGHANDLER(handler, signo, ctx) \
  (handler)((signo), SIGCONTEXT_EXTRA_ARGS (ctx))
