/* Software floating-point emulation.
   Return (unsigned long)(*a)
   Copyright (C) 1997,1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Richard Henderson (rth@cygnus.com) and
		  Jakub Jelinek (jj@ultra.linux.cz).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#define FP_ROUNDMODE FP_RND_ZERO
#include "soft-fp.h"
#include "quad.h"

unsigned long _Qp_qtoux(const long double *a)
{
  FP_DECL_EX;
  FP_DECL_Q(A);
  unsigned long r;

  FP_INIT_ROUNDMODE;
  FP_UNPACK_QP(A, a);
  FP_TO_INT_Q(r, A, 64, -1);
  QP_HANDLE_EXCEPTIONS(
	unsigned long rx;
  	__asm (
"	ldd [%1], %%f52\n"
"	ldd [%1+8], %%f54\n"
"	fqtoi %%f52, %%f60\n"
"	std %%f60, [%0]\n"
"	" : : "r" (&rx), "r" (a) : QP_CLOBBER);
	r = rx);

  return r;
}
