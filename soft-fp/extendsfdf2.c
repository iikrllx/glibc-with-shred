/* Software floating-point emulation.
   Return a converted to IEEE double
   Copyright (C) 1997,1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Richard Henderson (rth@cygnus.com) and
		  Jakub Jelinek (jj@ultra.linux.cz).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include "soft-fp.h"
#include "single.h"
#include "double.h"

double __extendsfdf2(float a)
{
  FP_DECL_EX;
  FP_DECL_S(A);
  FP_DECL_D(R);
  double r;

  FP_INIT_ROUNDMODE;
  FP_UNPACK_S(A, a);
#if _FP_W_TYPE_SIZE < _FP_FRACBITS_D
  FP_CONV(D,S,2,1,R,A);
#else
  FP_CONV(D,S,1,1,R,A);
#endif
  FP_PACK_D(r, R);
  FP_HANDLE_EXCEPTIONS;

  return r;
}
