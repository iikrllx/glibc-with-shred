/* Low-level statistical profiling support function.  Linux/ARM version.
   Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.
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

#include <signal.h>
#include <bits/armsigctx.h>

void
profil_counter (int signo, int _a2, int _a3, int _a4, union k_sigcontext sc)
{
  void *pc;
  if (sc.v20.magic == SIGCONTEXT_2_0_MAGIC)
    pc = (void *) sc.v20.reg.ARM_pc;
  else
    pc = (void *) sc.v21.arm_pc;
  profil_count (pc);
}
