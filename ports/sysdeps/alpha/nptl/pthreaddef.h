/* Copyright (C) 2003-2013 Free Software Foundation, Inc.
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
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

/* Default stack size.  */
#define ARCH_STACK_DEFAULT_SIZE	(4 * 1024 * 1024)

/* Required stack pointer alignment at beginning.  The ABI requires 16.  */
#define STACK_ALIGN		16

/* Minimal stack size after allocating thread descriptor and guard size.  */
#define MINIMAL_REST_STACK	4096

/* Alignment requirement for TCB.  */
#define TCB_ALIGNMENT		16

/* Location of current stack frame.  */
#define CURRENT_STACK_FRAME	__builtin_frame_address (0)

/* XXX Until we have a better place keep the definitions here.  */

/* While there is no such syscall.  */
#define __exit_thread_inline(val) \
  INLINE_SYSCALL (exit, 1, (val))
