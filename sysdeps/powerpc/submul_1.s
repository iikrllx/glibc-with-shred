 # Multiply a limb vector by a single limb, for PowerPC.
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

 # mp_limb_t mpn_submul_1 (mp_ptr res_ptr, mp_srcptr s1_ptr,
 #                         mp_size_t s1_size, mp_limb_t s2_limb)
 # Calculate res-s1*s2 and put result back in res; return carry.

	.align 2
	.globl __mpn_submul_1
	.type	 __mpn_submul_1,@function
__mpn_submul_1:
	mtctr	%r5

	lwz	%r0,0(%r4)
	mullw	%r7,%r0,%r6
	mulhwu	%r10,%r0,%r6
	lwz     %r9,0(%r3)
	subf 	%r8,%r7,%r9
	addc    %r7,%r7,%r8		# invert cy (r7 is junk)
	addi	%r3,%r3,-4		# adjust res_ptr
	bdz	Lend

Loop:	lwzu	%r0,4(%r4)
	stwu	%r8,4(%r3)
	mullw	%r8,%r0,%r6
	adde	%r7,%r8,%r10
	mulhwu	%r10,%r0,%r6
	lwz     %r9,4(%r3)
	addze   %r10,%r10
	subf    %r8,%r7,%r9
	addc    %r7,%r7,%r8		# invert cy (r7 is junk)
	bdnz	Loop

Lend:	stw	%r8,4(%r3)
	addze	%r3,%r10
	blr
