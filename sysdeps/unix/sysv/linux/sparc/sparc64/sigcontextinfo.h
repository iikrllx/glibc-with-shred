/* Copyright (C) 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jakub Jelinek <jj@ultra.linux.cz>, 1999.

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

#ifndef STACK_BIAS
#define STACK_BIAS 2047
#endif
#define SIGCONTEXT __siginfo_t *
#define GET_PC(ctx)	((void *) ctx->si_regs.tpc)
#define ADVANCE_STACK_FRAME(next) \
	((void *) &((struct reg_window *) (((unsigned long int) next)	      \
					   + STACK_BIAS))->ins[6])
#define GET_STACK(ctx)	((void *) ctx->si_regs.u_regs[14])
#define GET_FRAME(ctx)	ADVANCE_STACK_FRAME (GET_STACK (ctx))
