/* Second module for NODELETE test defining a unique symbol.
   Copyright (C) 2019-2022 Free Software Foundation, Inc.
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

#include "tst-dlopen-nodelete-reloc.h"

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

/* Just a flag here, not used for NODELETE processing.  */
bool may_finalize_mod7 = false;

extern template struct unique_symbol<6>;

/* Trigger the creation of a unique symbol reference.  This should
   cause tst-dlopen-nodelete-reloc-mod6.so to be marked as
   NODELETE.  */
int
global_function_mod7 (void)
{
  return unique_symbol<6>::value;
}

static void __attribute__ ((destructor))
fini (void)
{
  if (!may_finalize_mod7)
    {
      puts ("error: tst-dlopen-nodelete-reloc-mod7.so destructor"
            " called too early");
      _exit (1);
    }
}
