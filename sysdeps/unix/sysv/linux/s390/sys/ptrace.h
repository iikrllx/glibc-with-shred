/* `ptrace' debugger support interface.  Linux/S390 version.
   Copyright (C) 2000-2018 Free Software Foundation, Inc.
   Contributed by Denis Joseph Barrow (djbarrow@de.ibm.com).
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _SYS_PTRACE_H
#define _SYS_PTRACE_H	1

#include <features.h>
#include <bits/types.h>

__BEGIN_DECLS
#if defined _LINUX_PTRACE_H || defined _S390_PTRACE_H
/* Kludge to stop stuff gdb & strace compiles from getting upset
 */
# undef PTRACE_TRACEME
# undef PTRACE_PEEKTEXT
# undef PTRACE_PEEKDATA
# undef PTRACE_POKETEXT
# undef PTRACE_POKEDATA
# undef PTRACE_CONT
# undef PTRACE_KILL
# undef PTRACE_SINGLESTEP
# undef PTRACE_SINGLEBLOCK
# undef PTRACE_ATTACH
# undef PTRACE_DETACH
# undef PTRACE_SYSCALL
# undef PTRACE_SETOPTIONS
# undef PTRACE_GETEVENTMSG
# undef PTRACE_GETSIGINFO
# undef PTRACE_SETSIGINFO
# undef PTRACE_GETREGSET
# undef PTRACE_SETREGSET
# undef PTRACE_SEIZE
# undef PTRACE_INTERRUPT
# undef PTRACE_LISTEN
# undef PTRACE_PEEKSIGINFO
# undef PTRACE_GETSIGMASK
# undef PTRACE_SETSIGMASK
# undef PTRACE_SECCOMP_GET_FILTER
# undef PTRACE_PEEKUSR_AREA
# undef PTRACE_POKEUSR_AREA
# undef PTRACE_GET_LAST_BREAK
# undef PTRACE_ENABLE_TE
# undef PTRACE_DISABLE_TE
# undef PTRACE_TE_ABORT_RAND
# undef PTRACE_O_TRACESYSGOOD
# undef PTRACE_O_TRACEFORK
# undef PTRACE_O_TRACEVFORK
# undef PTRACE_O_TRACECLONE
# undef PTRACE_O_TRACEEXEC
# undef PTRACE_O_TRACEVFORKDONE
# undef PTRACE_O_TRACEEXIT
# undef PTRACE_O_TRACESECCOMP
# undef PTRACE_O_EXITKILL
# undef PTRACE_O_SUSPEND_SECCOMP
# undef PTRACE_O_MASK
# undef PTRACE_EVENT_FORK
# undef PTRACE_EVENT_VFORK
# undef PTRACE_EVENT_CLONE
# undef PTRACE_EVENT_EXEC
# undef PTRACE_EVENT_VFORK_DONE
# undef PTRACE_EVENT_EXIT
# undef PTRACE_EVENT_SECCOMP
# undef PTRACE_EVENT_STOP
# undef PTRACE_PEEKSIGINFO_SHARED
#endif
/* Type of the REQUEST argument to `ptrace.'  */
enum __ptrace_request
{
  /* Indicate that the process making this request should be traced.
     All signals received by this process can be intercepted by its
     parent, and its parent can use the other `ptrace' requests.  */
  PTRACE_TRACEME = 0,
#define PT_TRACE_ME PTRACE_TRACEME

  /* Return the word in the process's text space at address ADDR.  */
  PTRACE_PEEKTEXT = 1,
#define PT_READ_I PTRACE_PEEKTEXT

  /* Return the word in the process's data space at address ADDR.  */
  PTRACE_PEEKDATA = 2,
#define PT_READ_D PTRACE_PEEKDATA

  /* Return the word in the process's user area at offset ADDR.  */
  PTRACE_PEEKUSER = 3,
#define PT_READ_U PTRACE_PEEKUSER

  /* Write the word DATA into the process's text space at address ADDR.  */
  PTRACE_POKETEXT = 4,
#define PT_WRITE_I PTRACE_POKETEXT

  /* Write the word DATA into the process's data space at address ADDR.  */
  PTRACE_POKEDATA = 5,
#define PT_WRITE_D PTRACE_POKEDATA

  /* Write the word DATA into the process's user area at offset ADDR.  */
  PTRACE_POKEUSER = 6,
#define PT_WRITE_U PTRACE_POKEUSER

  /* Continue the process.  */
  PTRACE_CONT = 7,
#define PT_CONTINUE PTRACE_CONT

  /* Kill the process.  */
  PTRACE_KILL = 8,
#define PT_KILL PTRACE_KILL

  /* Single step the process.  */
  PTRACE_SINGLESTEP = 9,
#define PT_STEP PTRACE_SINGLESTEP

  /* Execute process until next taken branch.  */
  PTRACE_SINGLEBLOCK = 12,
#define PT_STEPBLOCK PTRACE_SINGLEBLOCK

  /* Attach to a process that is already running. */
  PTRACE_ATTACH = 16,
#define PT_ATTACH PTRACE_ATTACH

  /* Detach from a process attached to with PTRACE_ATTACH.  */
  PTRACE_DETACH = 17,
#define PT_DETACH PTRACE_DETACH

  /* Continue and stop at the next entry to or return from syscall.  */
  PTRACE_SYSCALL = 24,
#define PT_SYSCALL PTRACE_SYSCALL

  /* Set ptrace filter options.  */
  PTRACE_SETOPTIONS = 0x4200,
#define PT_SETOPTIONS PTRACE_SETOPTIONS

  /* Get last ptrace message.  */
  PTRACE_GETEVENTMSG = 0x4201,
#define PT_GETEVENTMSG PTRACE_GETEVENTMSG

  /* Get siginfo for process.  */
  PTRACE_GETSIGINFO = 0x4202,
#define PT_GETSIGINFO PTRACE_GETSIGINFO

  /* Set new siginfo for process.  */
  PTRACE_SETSIGINFO = 0x4203,
#define PT_SETSIGINFO PTRACE_SETSIGINFO

  /* Get register content.  */
  PTRACE_GETREGSET = 0x4204,
#define PTRACE_GETREGSET PTRACE_GETREGSET

  /* Set register content.  */
  PTRACE_SETREGSET = 0x4205,
#define PTRACE_SETREGSET PTRACE_SETREGSET

  /* Like PTRACE_ATTACH, but do not force tracee to trap and do not affect
     signal or group stop state.  */
  PTRACE_SEIZE = 0x4206,
#define PTRACE_SEIZE PTRACE_SEIZE

  /* Trap seized tracee.  */
  PTRACE_INTERRUPT = 0x4207,
#define PTRACE_INTERRUPT PTRACE_INTERRUPT

  /* Wait for next group event.  */
  PTRACE_LISTEN = 0x4208,
#define PTRACE_LISTEN PTRACE_LISTEN

  /* Retrieve siginfo_t structures without removing signals from a queue.  */
  PTRACE_PEEKSIGINFO = 0x4209,
#define PTRACE_PEEKSIGINFO PTRACE_PEEKSIGINFO

  /* Get the mask of blocked signals.  */
  PTRACE_GETSIGMASK = 0x420a,
#define PTRACE_GETSIGMASK PTRACE_GETSIGMASK

  /* Change the mask of blocked signals.  */
  PTRACE_SETSIGMASK = 0x420b,
#define PTRACE_SETSIGMASK PTRACE_SETSIGMASK

  /* Get seccomp BPF filters.  */
  PTRACE_SECCOMP_GET_FILTER = 0x420c,
#define PTRACE_SECCOMP_GET_FILTER PTRACE_SECCOMP_GET_FILTER

  PTRACE_PEEKUSR_AREA = 0x5000,
#define PTRACE_PEEKUSR_AREA PTRACE_PEEKUSR_AREA

  PTRACE_POKEUSR_AREA = 0x5001,
#define PTRACE_POKEUSR_AREA PTRACE_POKEUSR_AREA

  PTRACE_GET_LAST_BREAK = 0x5006,
#define PTRACE_GET_LAST_BREAK PTRACE_GET_LAST_BREAK

  PTRACE_ENABLE_TE = 0x5009,
#define PTRACE_ENABLE_TE PTRACE_ENABLE_TE

  PTRACE_DISABLE_TE = 0x5010,
#define PTRACE_DISABLE_TE PTRACE_DISABLE_TE

  PTRACE_TE_ABORT_RAND = 0x5011
#define PTRACE_TE_ABORT_RAND PTRACE_TE_ABORT_RAND
};


#include <bits/ptrace-shared.h>

__END_DECLS

#endif /* _SYS_PTRACE_H */
