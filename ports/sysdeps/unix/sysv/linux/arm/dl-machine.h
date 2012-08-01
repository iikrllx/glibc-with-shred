/* Machine-dependent ELF dynamic relocation inline functions.  ARM/Linux version
   Copyright (C) 1995-2012 Free Software Foundation, Inc.
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

#ifndef dl_machine_h

/* This definition is Linux-specific.  */
#define CLEAR_CACHE(BEG,END)                                            \
  INTERNAL_SYSCALL_ARM (cacheflush, , 3, (BEG), (END), 0)

/* The rest is just machine-specific.  */
#include <sysdeps/arm/dl-machine.h>

#endif
