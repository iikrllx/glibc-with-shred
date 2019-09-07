/* ss_flags values for stack_t.
   Copyright (C) 1998-2019 Free Software Foundation, Inc.
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

#ifndef _BITS_SS_FLAGS_H
#define _BITS_SS_FLAGS_H 1

#if !defined _SIGNAL_H && !defined _SYS_UCONTEXT_H
# error "Never include this file directly.  Use <signal.h> instead"
#endif

/* Possible values for `ss_flags.'.  */
enum
{
  SS_ONSTACK = 0x0001,
#define SS_ONSTACK	SS_ONSTACK
  SS_DISABLE = 0x0004
#define SS_DISABLE	SS_DISABLE
};

#endif /* bits/ss_flags.h */
