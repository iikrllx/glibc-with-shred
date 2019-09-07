/* Copyright (C) 2003-2019 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <sysdep.h>

/* Default stack size.  */
#define ARCH_STACK_DEFAULT_SIZE	(2 * 1024 * 1024)

/* Required stack pointer alignment at beginning.  */
#define STACK_ALIGN		8

/* Minimal stack size after allocating thread descriptor and guard size.  */
#define MINIMAL_REST_STACK	2048

/* Alignment requirement for TCB.  */
#define TCB_ALIGNMENT		8


/* Location of current stack frame.  */
#define CURRENT_STACK_FRAME	__builtin_frame_address (0)
