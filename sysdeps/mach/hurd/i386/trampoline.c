/* Set thread_state for sighandler, and sigcontext to recover.  i386 version.
   Copyright (C) 1994, 1995, 1996, 1997 Free Software Foundation, Inc.
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

#include <hurd/signal.h>
#include <hurd/userlink.h>
#include "thread_state.h"
#include <assert.h>
#include <errno.h>
#include "hurdfault.h"
#include "intr-msg.h"


struct sigcontext *
_hurd_setup_sighandler (struct hurd_sigstate *ss, __sighandler_t handler,
			int signo, struct hurd_signal_detail *detail,
			volatile int rpc_wait,
			struct machine_thread_all_state *state)
{
  __label__ trampoline, rpc_wait_trampoline, firewall;
  extern const void _hurd_intr_rpc_msg_in_trap;
  extern const void _hurd_intr_rpc_msg_cx_sp;
  extern const void _hurd_intr_rpc_msg_sp_restored;
  void *volatile sigsp;
  struct sigcontext *scp;
  struct
    {
      int signo;
      long int sigcode;
      struct sigcontext *scp;	/* Points to ctx, below.  */
      void *sigreturn_addr;
      void *sigreturn_returns_here;
      struct sigcontext *return_scp; /* Same; arg to sigreturn.  */
      struct sigcontext ctx;
      struct hurd_userlink link;
    } *stackframe;

  if (ss->context)
    {
      /* We have a previous sigcontext that sigreturn was about
	 to restore when another signal arrived.  We will just base
	 our setup on that.  */
      if (! _hurdsig_catch_memory_fault (ss->context))
	{
	  memcpy (&state->basic, &ss->context->sc_i386_thread_state,
		  sizeof (state->basic));
	  memcpy (&state->fpu, &ss->context->sc_i386_float_state,
		  sizeof (state->fpu));
	  state->set |= (1 << i386_THREAD_STATE) | (1 << i386_FLOAT_STATE);
	}
    }

  if (! machine_get_basic_state (ss->thread, state))
    return NULL;

  /* Save the original SP in the gratuitous `esp' slot.
     We may need to reset the SP (the `uesp' slot) to avoid clobbering an
     interrupted RPC frame.  */
  state->basic.esp = state->basic.uesp;

  if ((ss->actions[signo].sa_flags & SA_ONSTACK) &&
      !(ss->sigaltstack.ss_flags & (SA_DISABLE|SA_ONSTACK)))
    {
      sigsp = ss->sigaltstack.ss_sp + ss->sigaltstack.ss_size;
      ss->sigaltstack.ss_flags |= SA_ONSTACK;
      /* XXX need to set up base of new stack for
	 per-thread variables, cthreads.  */
    }
  /* This code has intimate knowledge of the special mach_msg system call
     done in intr-msg.c; that code does (see intr-msg.h):
					movl %esp, %ecx
					leal ARGS, %esp
	_hurd_intr_rpc_msg_cx_sp:	movl $-25, %eax
	_hurd_intr_rpc_msg_do_trap:	lcall $7, $0
	_hurd_intr_rpc_msg_in_trap:	movl %ecx, %esp
	_hurd_intr_rpc_msg_sp_restored:
     We must check for the window during which %esp points at the
     mach_msg arguments.  The space below until %ecx is used by
     the _hurd_intr_rpc_mach_msg frame, and must not be clobbered.  */
  else if (state->basic.eip >= (int) &_hurd_intr_rpc_msg_cx_sp &&
	   state->basic.eip < (int) &_hurd_intr_rpc_msg_sp_restored)
    /* The SP now points at the mach_msg args, but there is more stack
       space used below it.  The real SP is saved in %ecx; we must push the
       new frame below there, and restore that value as the SP on
       sigreturn.  */
    sigsp = (char *) (state->basic.uesp = state->basic.ecx);
  else
    sigsp = (char *) state->basic.uesp;

  /* Push the arguments to call `trampoline' on the stack.  */
  sigsp -= sizeof (*stackframe);
  stackframe = sigsp;

  if (_hurdsig_catch_memory_fault (stackframe))
    {
      /* We got a fault trying to write the stack frame.
	 We cannot set up the signal handler.
	 Returning NULL tells our caller, who will nuke us with a SIGILL.  */
      return NULL;
    }
  else
    {
      int ok;

      extern void _hurdsig_longjmp_from_handler (void *, jmp_buf, int);

      /* Add a link to the thread's active-resources list.  We mark this as
	 the only user of the "resource", so the cleanup function will be
	 called by any longjmp which is unwinding past the signal frame.
	 The cleanup function (in sigunwind.c) will make sure that all the
	 appropriate cleanups done by sigreturn are taken care of.  */
      stackframe->link.cleanup = &_hurdsig_longjmp_from_handler;
      stackframe->link.cleanup_data = &stackframe->ctx;
      stackframe->link.resource.next = NULL;
      stackframe->link.resource.prevp = NULL;
      stackframe->link.thread.next = ss->active_resources;
      stackframe->link.thread.prevp = &ss->active_resources;
      if (stackframe->link.thread.next)
	stackframe->link.thread.next->thread.prevp
	  = &stackframe->link.thread.next;
      ss->active_resources = &stackframe->link;

      /* Set up the arguments for the signal handler.  */
      stackframe->signo = signo;
      stackframe->sigcode = detail->code;
      stackframe->scp = stackframe->return_scp = scp = &stackframe->ctx;
      stackframe->sigreturn_addr = &__sigreturn;
      stackframe->sigreturn_returns_here = &&firewall; /* Crash on return.  */

      /* Set up the sigcontext from the current state of the thread.  */

      scp->sc_onstack = ss->sigaltstack.ss_flags & SA_ONSTACK ? 1 : 0;

      /* struct sigcontext is laid out so that starting at sc_gs mimics a
	 struct i386_thread_state.  */
      memcpy (&scp->sc_i386_thread_state,
	      &state->basic, sizeof (state->basic));

      /* struct sigcontext is laid out so that starting at sc_fpkind mimics
	 a struct i386_float_state.  */
      ok = machine_get_state (ss->thread, state, i386_FLOAT_STATE,
			      &state->fpu, &scp->sc_i386_float_state,
			      sizeof (state->fpu));

      _hurdsig_end_catch_fault ();

      if (! ok)
	return NULL;
    }

  /* Modify the thread state to call the trampoline code on the new stack.  */
  if (rpc_wait)
    {
      /* The signalee thread was blocked in a mach_msg_trap system call,
	 still waiting for a reply.  We will have it run the special
	 trampoline code which retries the message receive before running
	 the signal handler.

	 To do this we change the OPTION argument on its stack to enable only
	 message reception, since the request message has already been
	 sent.  */

      struct mach_msg_trap_args *args = (void *) state->basic.esp;

      if (_hurdsig_catch_memory_fault (args))
	{
	  /* Faulted accessing ARGS.  Bomb.  */
	  return NULL;
	}

      assert (args->option & MACH_RCV_MSG);
      /* Disable the message-send, since it has already completed.  The
	 calls we retry need only wait to receive the reply message.  */
      args->option &= ~MACH_SEND_MSG;

      /* Limit the time to receive the reply message, in case the server
	 claimed that `interrupt_operation' succeeded but in fact the RPC
	 is hung.  */
      args->option |= MACH_RCV_TIMEOUT;
      args->timeout = _hurd_interrupted_rpc_timeout;

      _hurdsig_end_catch_fault ();

      state->basic.eip = (int) &&rpc_wait_trampoline;
      /* The reply-receiving trampoline code runs initially on the original
	 user stack.  We pass it the signal stack pointer in %ebx.  */
      state->basic.uesp = state->basic.esp; /* Restore mach_msg syscall SP.  */
      state->basic.ebx = (int) sigsp;
      /* After doing the message receive, the trampoline code will need to
	 update the %eax value to be restored by sigreturn.  To simplify
	 the assembly code, we pass the address of its slot in SCP to the
	 trampoline code in %ecx.  */
      state->basic.ecx = (int) &scp->sc_eax;
    }
  else
    {
      state->basic.eip = (int) &&trampoline;
      state->basic.uesp = (int) sigsp;
    }
  /* We pass the handler function to the trampoline code in %edx.  */
  state->basic.edx = (int) handler;

  return scp;

  /* The trampoline code follows.  This is not actually executed as part of
     this function, it is just convenient to write it that way.  */

 rpc_wait_trampoline:
  /* This is the entry point when we have an RPC reply message to receive
     before running the handler.  The MACH_MSG_SEND bit has already been
     cleared in the OPTION argument on our stack.  The interrupted user
     stack pointer has not been changed, so the system call can find its
     arguments; the signal stack pointer is in %ebx.  For our convenience,
     %ecx points to the sc_eax member of the sigcontext.  */
  asm volatile
    (/* Retry the interrupted mach_msg system call.  */
     "movl $-25, %eax\n"	/* mach_msg_trap */
     "lcall $7, $0\n"
     /* When the sigcontext was saved, %eax was MACH_RCV_INTERRUPTED.  But
	now the message receive has completed and the original caller of
	the RPC (i.e. the code running when the signal arrived) needs to
	see the final return value of the message receive in %eax.  So
	store the new %eax value into the sc_eax member of the sigcontext
	(whose address is in %ecx to make this code simpler).  */
     "movl %eax, (%ecx)\n"
     /* Switch to the signal stack.  */
     "movl %ebx, %esp\n");

 trampoline:
  /* Entry point for running the handler normally.  The arguments to the
     handler function are already on the top of the stack:

       0(%esp)	SIGNO
       4(%esp)	SIGCODE
       8(%esp)	SCP
     */
  asm volatile
    ("call *%edx\n"		/* Call the handler function.  */
     "addl $12, %esp\n"		/* Pop its args.  */
     /* The word at the top of stack is &__sigreturn; following are a dummy
	word to fill the slot for the address for __sigreturn to return to,
	and a copy of SCP for __sigreturn's argument.  "Return" to calling
	__sigreturn (SCP); this call never returns.  */
     "ret");

 firewall:
  asm volatile ("hlt");

  /* NOTREACHED */
  return NULL;
}
