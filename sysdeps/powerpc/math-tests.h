/* Configuration for math tests.  PowerPC version.
   Copyright (C) 2013-2018 Free Software Foundation, Inc.
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

/* On PowerPC, in versions of GCC up to at least 4.7.2, a type cast -- which is
   a IEEE 754-2008 general-computational convertFormat operation (IEEE
   754-2008, 5.4.2) -- does not turn a sNaN into a qNaN (whilst raising an
   INVALID exception), which is contrary to IEEE 754-2008 5.1 and 7.2.  This
   renders certain tests infeasible in this scenario.
   <http://gcc.gnu.org/PR56828>.  */
#define SNAN_TESTS_TYPE_CAST	0

#ifndef __NO_FPRS__
/* Setting exception flags in FPSCR results in enabled traps for those
   exceptions being taken.  */
# define EXCEPTION_SET_FORCES_TRAP 1
#endif

#include_next <math-tests.h>
