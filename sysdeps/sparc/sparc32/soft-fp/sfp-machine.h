/* Machine-dependent software floating-point definitions.
   Sparc userland (_Q_*) version.
   Copyright (C) 1997,1998,1999, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Richard Henderson (rth@cygnus.com),
		  Jakub Jelinek (jj@ultra.linux.cz) and
		  David S. Miller (davem@redhat.com).

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

#include <fpu_control.h>

#define _FP_W_TYPE_SIZE		32
#define _FP_W_TYPE		unsigned long
#define _FP_WS_TYPE		signed long
#define _FP_I_TYPE		long

#define _FP_MUL_MEAT_S(R,X,Y)				\
  _FP_MUL_MEAT_1_wide(_FP_WFRACBITS_S,R,X,Y,umul_ppmm)
#define _FP_MUL_MEAT_D(R,X,Y)				\
  _FP_MUL_MEAT_2_wide(_FP_WFRACBITS_D,R,X,Y,umul_ppmm)
#define _FP_MUL_MEAT_Q(R,X,Y)				\
  _FP_MUL_MEAT_4_wide(_FP_WFRACBITS_Q,R,X,Y,umul_ppmm)

#define _FP_DIV_MEAT_S(R,X,Y)	_FP_DIV_MEAT_1_udiv(S,R,X,Y)
#define _FP_DIV_MEAT_D(R,X,Y)	_FP_DIV_MEAT_2_udiv(D,R,X,Y)
#define _FP_DIV_MEAT_Q(R,X,Y)	_FP_DIV_MEAT_4_udiv(Q,R,X,Y)

#define _FP_NANFRAC_S		((_FP_QNANBIT_S << 1) - 1)
#define _FP_NANFRAC_D		((_FP_QNANBIT_D << 1) - 1), -1
#define _FP_NANFRAC_Q		((_FP_QNANBIT_Q << 1) - 1), -1, -1, -1
#define _FP_NANSIGN_S		0
#define _FP_NANSIGN_D		0
#define _FP_NANSIGN_Q		0

#define _FP_KEEPNANFRACP 1

/* If one NaN is signaling and the other is not,
 * we choose that one, otherwise we choose X.
 */
/* For _Qp_* and _Q_*, this should prefer X, for
 * CPU instruction emulation this should prefer Y.
 * (see SPAMv9 B.2.2 section).
 */
#define _FP_CHOOSENAN(fs, wc, R, X, Y, OP)			\
  do {								\
    if ((_FP_FRAC_HIGH_RAW_##fs(X) & _FP_QNANBIT_##fs)		\
	&& !(_FP_FRAC_HIGH_RAW_##fs(Y) & _FP_QNANBIT_##fs))	\
      {								\
	R##_s = Y##_s;						\
	_FP_FRAC_COPY_##wc(R,Y);				\
      }								\
    else							\
      {								\
	R##_s = X##_s;						\
	_FP_FRAC_COPY_##wc(R,X);				\
      }								\
    R##_c = FP_CLS_NAN;						\
  } while (0)

/* Some assembly to speed things up. */
#define __FP_FRAC_ADD_3(r2,r1,r0,x2,x1,x0,y2,y1,y0)			\
  __asm__ ("addcc %r7,%8,%2\n\
	    addxcc %r5,%6,%1\n\
	    addx %r3,%4,%0"						\
	   : "=r" ((USItype)(r2)),					\
	     "=&r" ((USItype)(r1)),					\
	     "=&r" ((USItype)(r0))					\
	   : "%rJ" ((USItype)(x2)),					\
	     "rI" ((USItype)(y2)),					\
	     "%rJ" ((USItype)(x1)),					\
	     "rI" ((USItype)(y1)),					\
	     "%rJ" ((USItype)(x0)),					\
	     "rI" ((USItype)(y0))					\
	   : "cc")

#define __FP_FRAC_SUB_3(r2,r1,r0,x2,x1,x0,y2,y1,y0)			\
  __asm__ ("subcc %r7,%8,%2\n\
	    subxcc %r5,%6,%1\n\
	    subx %r3,%4,%0"						\
	   : "=r" ((USItype)(r2)),					\
	     "=&r" ((USItype)(r1)),					\
	     "=&r" ((USItype)(r0))					\
	   : "%rJ" ((USItype)(x2)),					\
	     "rI" ((USItype)(y2)),					\
	     "%rJ" ((USItype)(x1)),					\
	     "rI" ((USItype)(y1)),					\
	     "%rJ" ((USItype)(x0)),					\
	     "rI" ((USItype)(y0))					\
	   : "cc")

#define __FP_FRAC_ADD_4(r3,r2,r1,r0,x3,x2,x1,x0,y3,y2,y1,y0)		\
  do {									\
    /* We need to fool gcc,  as we need to pass more than 10		\
       input/outputs.  */						\
    register USItype _t1 __asm__ ("g1"), _t2 __asm__ ("g2");		\
    __asm__ __volatile__ ("\
	    addcc %r8,%9,%1\n\
	    addxcc %r6,%7,%0\n\
	    addxcc %r4,%5,%%g2\n\
	    addx %r2,%3,%%g1"						\
	   : "=&r" ((USItype)(r1)),					\
	     "=&r" ((USItype)(r0))					\
	   : "%rJ" ((USItype)(x3)),					\
	     "rI" ((USItype)(y3)),					\
	     "%rJ" ((USItype)(x2)),					\
	     "rI" ((USItype)(y2)),					\
	     "%rJ" ((USItype)(x1)),					\
	     "rI" ((USItype)(y1)),					\
	     "%rJ" ((USItype)(x0)),					\
	     "rI" ((USItype)(y0))					\
	   : "cc", "g1", "g2");						\
    __asm__ __volatile__ ("" : "=r" (_t1), "=r" (_t2));			\
    r3 = _t1; r2 = _t2;							\
  } while (0)

#define __FP_FRAC_SUB_4(r3,r2,r1,r0,x3,x2,x1,x0,y3,y2,y1,y0)		\
  do {									\
    /* We need to fool gcc,  as we need to pass more than 10		\
       input/outputs.  */						\
    register USItype _t1 __asm__ ("g1"), _t2 __asm__ ("g2");		\
    __asm__ __volatile__ ("\
	    subcc %r8,%9,%1\n\
	    subxcc %r6,%7,%0\n\
	    subxcc %r4,%5,%%g2\n\
	    subx %r2,%3,%%g1"						\
	   : "=&r" ((USItype)(r1)),					\
	     "=&r" ((USItype)(r0))					\
	   : "%rJ" ((USItype)(x3)),					\
	     "rI" ((USItype)(y3)),					\
	     "%rJ" ((USItype)(x2)),					\
	     "rI" ((USItype)(y2)),					\
	     "%rJ" ((USItype)(x1)),					\
	     "rI" ((USItype)(y1)),					\
	     "%rJ" ((USItype)(x0)),					\
	     "rI" ((USItype)(y0))					\
	   : "cc", "g1", "g2");						\
    __asm__ __volatile__ ("" : "=r" (_t1), "=r" (_t2));			\
    r3 = _t1; r2 = _t2;							\
  } while (0)

#define __FP_FRAC_DEC_3(x2,x1,x0,y2,y1,y0) __FP_FRAC_SUB_3(x2,x1,x0,x2,x1,x0,y2,y1,y0)

#define __FP_FRAC_DEC_4(x3,x2,x1,x0,y3,y2,y1,y0) __FP_FRAC_SUB_4(x3,x2,x1,x0,x3,x2,x1,x0,y3,y2,y1,y0)

#define __FP_FRAC_ADDI_4(x3,x2,x1,x0,i)					\
  __asm__ ("addcc %3,%4,%3\n\
	    addxcc %2,%%g0,%2\n\
	    addxcc %1,%%g0,%1\n\
	    addx %0,%%g0,%0"						\
	   : "=&r" ((USItype)(x3)),					\
	     "=&r" ((USItype)(x2)),					\
	     "=&r" ((USItype)(x1)),					\
	     "=&r" ((USItype)(x0))					\
	   : "rI" ((USItype)(i)),					\
	     "0" ((USItype)(x3)),					\
	     "1" ((USItype)(x2)),					\
	     "2" ((USItype)(x1)),					\
	     "3" ((USItype)(x0))					\
	   : "cc")

/* Obtain the current rounding mode. */
#ifndef FP_ROUNDMODE
#define FP_ROUNDMODE	((_fcw >> 30) & 0x3)
#endif

/* Exception flags. */
#define FP_EX_INVALID		(1 << 4)
#define FP_EX_OVERFLOW		(1 << 3)
#define FP_EX_UNDERFLOW		(1 << 2)
#define FP_EX_DIVZERO		(1 << 1)
#define FP_EX_INEXACT		(1 << 0)

#define _FP_DECL_EX	fpu_control_t _fcw

#define FP_INIT_ROUNDMODE					\
do {								\
  _FPU_GETCW(_fcw);						\
} while (0)

/* Simulate exceptions using double arithmetics. */
extern double ___Q_simulate_exceptions(int exc);

#define FP_HANDLE_EXCEPTIONS					\
do {								\
  if (!_fex)							\
    {								\
      /* This is the common case, so we do it inline.		\
       * We need to clear cexc bits if any.			\
       */							\
      extern unsigned long long ___Q_numbers[];			\
      __asm__ __volatile__("\
      	ldd [%0], %%f30\n\
      	faddd %%f30, %%f30, %%f30\
      	" : : "r" (___Q_numbers) : "f30");			\
    }								\
  else								\
    {								\
      __asm__ __volatile__("\
        mov %0, %%o0\n\
        mov %%o7, %%g1\n\
        call ___Q_simulate_exceptions\n\
         mov %%g1, %%o7\
        " : : "r" (_fex) :					\
        "g1", "g2", "g3", "g4", "g5", "o0", 			\
        "o1", "o2", "o3", "o4", "o5", "cc");			\
    }								\
} while (0)
