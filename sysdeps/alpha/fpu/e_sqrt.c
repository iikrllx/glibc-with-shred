/* Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.
   Contributed by David Mosberger (davidm@cs.arizona.edu).

   This file is part of the GNU C Library.

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


#if !defined(_IEEE_FP_INEXACT)

/*
 * This version is much faster than generic sqrt implementation, but
 * it doesn't handle the inexact flag.  It doesn't handle exceptional
 * values either, but will defer to the full ieee754_sqrt routine which
 * can.
 */

/* Careful with rearranging this without consulting the assembly below.  */
const static struct sqrt_data_struct {
	unsigned long dn, up, half, almost_three_half;
	unsigned long one_and_a_half, two_to_minus_30, one, nan;
	const int T2[64];
} sqrt_data = {
	0x3fefffffffffffff,	/* __dn = nextafter(1,-Inf) */
	0x3ff0000000000001,	/* __up = nextafter(1,+Inf) */
	0x3fe0000000000000,	/* half */
	0x3ff7ffffffc00000,	/* almost_three_half = 1.5-2^-30 */
	0x3ff8000000000000,	/* one_and_a_half */
	0x3e10000000000000,	/* two_to_minus_30 */
	0x3ff0000000000000,	/* one */
	0xffffffffffffffff,	/* nan */

	{ 0x1500, 0x2ef8, 0x4d67, 0x6b02, 0x87be, 0xa395, 0xbe7a, 0xd866,
	0xf14a, 0x1091b,0x11fcd,0x13552,0x14999,0x15c98,0x16e34,0x17e5f,
	0x18d03,0x19a01,0x1a545,0x1ae8a,0x1b5c4,0x1bb01,0x1bfde,0x1c28d,
	0x1c2de,0x1c0db,0x1ba73,0x1b11c,0x1a4b5,0x1953d,0x18266,0x16be0,
	0x1683e,0x179d8,0x18a4d,0x19992,0x1a789,0x1b445,0x1bf61,0x1c989,
	0x1d16d,0x1d77b,0x1dddf,0x1e2ad,0x1e5bf,0x1e6e8,0x1e654,0x1e3cd,
	0x1df2a,0x1d635,0x1cb16,0x1be2c,0x1ae4e,0x19bde,0x1868e,0x16e2e,
	0x1527f,0x1334a,0x11051,0xe951, 0xbe01, 0x8e0d, 0x5924, 0x1edd }
};

asm ("\
  /* Define offsets into the structure defined in C above.  */
	$DN = 0*8
	$UP = 1*8
	$HALF = 2*8
	$ALMOST_THREE_HALF = 3*8
	$NAN = 7*8
	$T2 = 8*8

  /* Stack variables.  */
	$K = 0
	$Y = 8

	.text
	.align	5
	.globl	__ieee754_sqrt
	.ent	__ieee754_sqrt
__ieee754_sqrt:
	ldgp	$29, 0($27)
	subq	$sp, 16, $sp
	.frame	$sp, 16, $26, 0\n"
#ifdef PROF
"	lda	$28, _mcount
	jsr	$28, ($28), _mcount\n"
#endif
"	.prologue 1

	.align 4
	stt	$f16, $K($sp)		# e0    :
	mult	$f31, $f31, $f31	# .. fm :
	lda	$4, sqrt_data		# e0    :
	fblt	$f16, $fixup		# .. fa :

	ldah	$2, 0x5fe8		# e0    :
	ldq	$3, $K($sp)		# .. e1 :
	ldt	$f12, $HALF($4)		# e0    :
	ldt	$f18, $ALMOST_THREE_HALF($4)	# .. e1 :

	sll	$3, 52, $5		# e0    :
	lda	$6, 0x7fd		# .. e1 :
	fnop				# .. fa :
	fnop				# .. fm :

	subq	$5, 1, $5		# e1    :
	srl	$3, 33, $1		# .. e0 :
	cmpule	$5, $6, $5		# e0    :
	beq	$5, $fixup		# .. e1 :

	mult	$f16, $f12, $f11	# fm    : $f11 = x * 0.5
	subl	$2, $1, $2		# .. e0 :
	addt	$f12, $f12, $f17	# .. fa : $f17 = 1.0
	srl	$2, 12, $1		# e0    :

	and	$1, 0xfc, $1		# e0    :
	addq	$1, $4, $1		# e1    :
	ldl	$1, $T2($1)		# e0    :
	addt	$f12, $f17, $f15	# .. fa : $f15 = 1.5

	subl	$2, $1, $2		# e0    :
	ldt	$f14, $DN($4)		# .. e1 :
	sll	$2, 32, $2		# e0    :
	stq	$2, $Y($sp)		# e0    :

	ldt	$f13, $Y($sp)		# e0    :
	mult/su	$f11, $f13, $f10	# fm   2: $f10 = (x * 0.5) * y
	mult	$f10, $f13, $f10	# fm   4: $f10 = ((x * 0.5) * y) * y
	subt	$f15, $f10, $f1		# fa   4: $f1 = (1.5 - 0.5*x*y*y)

	mult	$f13, $f1, $f13         # fm   4: yp = y*(1.5 - 0.5*x*y*y)
 	mult/su	$f11, $f13, $f1		# fm   4: $f11 = x * 0.5 * yp
	mult	$f1, $f13, $f11		# fm   4: $f11 = (x * 0.5 * yp) * yp
	subt	$f18, $f11, $f1		# fa   4: $f1= (1.5-2^-30) - 0.5*x*yp*yp

	mult	$f13, $f1, $f13		# fm   4: ypp = $f13 = yp*$f1
	subt	$f15, $f12, $f1		# .. fa : $f1 = (1.5 - 0.5)
	ldt	$f15, $UP($4)		# .. e0 :
	mult/su	$f16, $f13, $f10	# fm   4: z = $f10 = x * ypp

	mult	$f10, $f13, $f11	# fm   4: $f11 = z*ypp
	mult	$f10, $f12, $f12	# fm    : $f12 = z*0.5
	subt	$f1, $f11, $f1		# fa   4: $f1 = 1 - z*ypp
	mult	$f12, $f1, $f12		# fm   4: $f12 = z*0.5*(1 - z*ypp)

	addt	$f10, $f12, $f0		# fa   4: zp=res= z + z*0.5*(1 - z*ypp)
	mult/c	$f0, $f14, $f12		# fm   4: zmi = zp * DN
	mult/c	$f0, $f15, $f11		# fm    : zpl = zp * UP
	mult/c	$f0, $f12, $f1		# fm    : $f1 = zp * zmi

	mult/c	$f0, $f11, $f15		# fm    : $f15 = zp * zpl
	subt/su	$f1, $f16, $f13		# .. fa : y1 = zp*zmi - x
	subt/su	$f15, $f16, $f14	# fa   4: y2 = zp*zpl - x
	fcmovge	$f13, $f12, $f0		# fa   3: res = (y1 >= 0) ? zmi : res

	fcmovlt	$f14, $f11, $f0		# fa   4: res = (y2 <  0) ? zpl : res
	addq	$sp, 16, $sp		# .. e0 :
	ret				# .. e1 :

	.align 4
$fixup:
	addq	$sp, 16, $sp
	br	"ASM_ALPHA_NG_SYMBOL_PREFIX"__full_ieee754_sqrt..ng

	.end	__ieee754_sqrt");

static double __full_ieee754_sqrt(double) __attribute__((unused));
#define __ieee754_sqrt __full_ieee754_sqrt

#endif /* _IEEE_FP_INEXACT */

#include <sysdeps/ieee754/dbl-64/e_sqrt.c>
