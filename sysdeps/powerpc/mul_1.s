 # Multiply a limb vector by a limb, for PowerPC.
 # Copyright (C) 1993, 1994, 1995, 1997 Free Software Foundation, Inc.
 # This file is part of the GNU C Library.
 #
 # The GNU C Library is free software; you can redistribute it and/or
 # modify it under the terms of the GNU Library General Public License as
 # published by the Free Software Foundation; either version 2 of the
 # License, or (at your option) any later version.
 #
 # The GNU C Library is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # Library General Public License for more details.
 #
 # You should have received a copy of the GNU Library General Public
 # License along with the GNU C Library; see the file COPYING.LIB.  If not,
 # write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 # Boston, MA 02111-1307, USA.

 # mp_limb_t mpn_mul_1 (mp_ptr res_ptr, mp_srcptr s1_ptr,
 #                      mp_size_t s1_size, mp_limb_t s2_limb)
 # Calculate s1*s2 and put result in res_ptr; return carry.

	.align 2
	.globl __mpn_mul_1
	.type	 __mpn_mul_1,@function

__mpn_mul_1:
	mtctr	%r5

	lwz	%r0,0(%r4)
	mullw	%r7,%r0,%r6
	mulhwu	%r10,%r0,%r6
	addi	%r3,%r3,-4		# adjust res_ptr
	addic	%r5,%r5,0		# clear cy with dummy insn
	bdz	Lend

Loop:	lwzu	%r0,4(%r4)
	stwu	%r7,4(%r3)
	mullw	%r8,%r0,%r6
	adde	%r7,%r8,%r10
	mulhwu	%r10,%r0,%r6
	bdnz	Loop

Lend:	stw	%r7,4(%r3)
	addze	%r3,%r10
	blr
