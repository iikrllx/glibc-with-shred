/* Return backtrace of current program state.
   Copyright (C) 1998, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#include <execinfo.h>
#include <bp-checks.h>


/* This is a global variable set at program start time.  It marks the
   highest used stack address.  */
extern void *__libc_stack_end;


/* This is the stack alyout we see with every stack frame.

            +-----------------+        +-----------------+
    %ebp -> | %ebp last frame--------> | %ebp last frame--->...
            |                 |        |                 |
            | return address  |        | return address  |
            +-----------------+        +-----------------+
*/
struct layout
{
  struct layout *__unbounded next;
  void *__unbounded return_address;
};

int
__backtrace (array, size)
     void **array;
     int size;
{
  /* We assume that all the code is generated with frame pointers set.  */
  register void *ebp __asm__ ("ebp");
  register void *esp __asm__ ("esp");
  struct layout *current;
  int cnt = 0;

  /* We skip the call to this function, it makes no sense to record it.  */
  current = BOUNDED_1 ((struct layout *) ebp);
  while (cnt < size)
    {
      if ((void *) current < esp || (void *) current > __libc_stack_end)
	/* This means the address is out of range.  Note that for the
	   toplevel we see a frame pointer with value NULL which clearly is
	   out of range.  */
	break;

      array[cnt++] = current->return_address;

      current = current->next;
    }

  return cnt;
}
weak_alias (__backtrace, backtrace)
