 # Add two limb vectors of equal, non-zero length for PowerPC.
 # Copyright (C) 1997 Free Software Foundation, Inc.
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

 # mp_limb_t mpn_add_n (mp_ptr res_ptr, mp_srcptr s1_ptr, mp_srcptr s2_ptr,
 #                      mp_size_t size)
 # Calculate s1+s2 and put result in res_ptr; return carry, 0 or 1.

 # Note on optimisation: This code is optimal for the 601.  Almost every other
 # possible 2-unrolled inner loop will not be.  Also, watch out for the
 # alignment...

	.align 3
	.globl __mpn_add_n
	.type	 __mpn_add_n,@function
__mpn_add_n:
 # Set up for loop below.
	mtcrf 0x01,%r6
	srwi. %r7,%r6,1
	li    %r10,0
	mtctr %r7
	bt    31,2f

 # Clear the carry.
	addic %r0,%r0,0
 # Adjust pointers for loop.
	addi  %r3,%r3,-4
	addi  %r4,%r4,-4
	addi  %r5,%r5,-4
	b     0f

2:	lwz  %r7,0(%r5)
	lwz  %r6,0(%r4)
	addc %r6,%r6,%r7
	stw  %r6,0(%r3)
        beq  1f

 # The loop.

 # Align start of loop to an odd word boundary to guarantee that the
 # last two words can be fetched in one access (for 601).
0:	lwz  %r9,4(%r4)
	lwz  %r8,4(%r5)
	lwzu %r6,8(%r4)
	lwzu %r7,8(%r5)
	adde %r8,%r9,%r8
	stw  %r8,4(%r3)
	adde %r6,%r6,%r7
	stwu %r6,8(%r3)
	bdnz 0b
 # return the carry
1:	addze %r3,%r10
	blr
