/* Copyright (C) 1994 Free Software Foundation, Inc.
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

/* Signal handlers are actually called:
   void handler (int sig, int code, struct sigcontext *scp);  */

/* State of this thread when the signal was taken.  */
struct sigcontext
  {
    int sc_onstack;		/* Nonzero if running on sigstack.  */
    sigset_t sc_mask;		/* Blocked signals to restore.  */

    /* MiG reply port this thread is using.  */
    unsigned int sc_reply_port;

    /* Port this thread is doing an interruptible RPC on.  */
    unsigned int sc_intr_port;

    /* The rest of this structure is written to be laid out identically
       to:
    	{
	  struct mips_thread_state ts;
	  struct mips_exc_state es;
	  struct mips_float_state fs;
	}
       trampoline.c knows this, so it must be changed if this changes.  */
    int sc_gpr[31];		/* "General" registers; [0] is r1.  */
    int sc_mdlo, sc_mdhi;	/* High and low multiplication results.  */
    int sc_pc;			/* Instruction pointer.  */

    /* struct mips_exc_state */
    unsigned int sc_cause;	/* Machine-level trap code.  */
#define SC_CAUSE_SST	0x00000044
    unsigned int sc_badvaddr;
    unsigned int sc_coproc_used; /* Which coprocessors the thread has used.  */
#define SC_COPROC_USE_COP0	1 /* (by definition) */
#define SC_COPROC_USE_COP1	2 /* FPA */
#define	SC_COPROC_USE_FPU	SC_COPROC_USE_COP1
#define SC_COPROC_USE_COP2	4
#define SC_COPROC_USE_COP3	8

    /* struct mips_float_state */
    int sc_fpr[32];		/* FP registers.  */
    int sc_fpcsr;		/* FPU status register.  */
    int sc_fpeir;		/* FP exception instruction register.  */
  };
