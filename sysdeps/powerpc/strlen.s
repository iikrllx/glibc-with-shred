 # Optimized strlen implementation for PowerPC.
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

 # The algorithm here uses the following techniques:
 #
 # 1) Given a word 'x', we can test to see if it contains any 0 bytes
 #    by subtracting 0x01010101, and seeing if any of the high bits of each
 #    byte changed from 0 to 1. This works because the least significant
 #    0 byte must have had no incoming carry (otherwise it's not the least
 #    significant), so it is 0x00 - 0x01 == 0xff. For all other
 #    byte values, either they have the high bit set initially, or when
 #    1 is subtracted you get a value in the range 0x00-0x7f, none of which
 #    have their high bit set. The expression here is
 #    (x + 0xfefefeff) & ~(x | 0x7f7f7f7f), which gives 0x00000000 when
 #    there were no 0x00 bytes in the word.
 #
 # 2) Given a word 'x', we can test to see _which_ byte was zero by
 #    calculating ~(((x & 0x7f7f7f7f) + 0x7f7f7f7f) | x | 0x7f7f7f7f).
 #    This produces 0x80 in each byte that was zero, and 0x00 in all
 #    the other bytes. The '| 0x7f7f7f7f' clears the low 7 bits in each
 #    byte, and the '| x' part ensures that bytes with the high bit set
 #    produce 0x00. The addition will carry into the high bit of each byte
 #    iff that byte had one of its low 7 bits set. We can then just see
 #    which was the most significant bit set and divide by 8 to find how
 #    many to add to the index.
 #    This is from the book 'The PowerPC Compiler Writer's Guide',
 #    by Steve Hoxey, Faraydon Karim, Bill Hay and Hank Warren.
 #
 # We deal with strings not aligned to a word boundary by taking the
 # first word and ensuring that bytes not part of the string
 # are treated as nonzero. To allow for memory latency, we unroll the
 # loop a few times, being careful to ensure that we do not read ahead
 # across cache line boundaries.
 #
 # Questions to answer:
 # 1) How long are strings passed to strlen? If they're often really long,
 # we should probably use cache management instructions and/or unroll the
 # loop more. If they're often quite short, it might be better to use
 # fact (2) in the inner loop than have to recalculate it.
 # 2) How popular are bytes with the high bit set? If they are very rare,
 # on some processors it might be useful to use the simpler expression
 # ~((x - 0x01010101) | 0x7f7f7f7f) (that is, on processors with only one
 # ALU), but this fails when any character has its high bit set.

 # Some notes on register usage: Under the SVR4 ABI, we can use registers
 # 0 and 3 through 12 (so long as we don't call any procedures) without
 # saving them. We can also use registers 14 through 31 if we save them.
 # We can't use r1 (it's the stack pointer), nor r2 or r13 because the user
 # program may expect them to be hold their usual value if we get sent
 # a signal. Integer parameters are passed in r3 through r10.
 # We can use condition registers cr0, cr1, cr5, cr6, and cr7 without saving
 # them, the others we must save.

	.section ".text"
	.align 3
	.globl strlen
	.type strlen,@function
strlen:
 # On entry, r3 points to the string, and it's left that way.
 # We use r6 to store 0x01010101, and r7 to store 0x7f7f7f7f.
 # r4 is used to keep the current index into the string; r5 holds
 # the number of padding bits we prepend to the string to make it
 # start at a word boundary. r8 holds the 'current' word.
 # r9-12 are temporaries. r0 is used as a temporary and for discarded
 # results.
	clrrwi 4,3,2
	lis 6,0xfeff
	lis 7,0x7f7f
	rlwinm 10,3,0,29,29
	lwz 8,0(4)
	addi 7,7,0x7f7f
	rlwinm 5,3,3,27,28
	cmpwi 1,10,0
	li 9,-1
 # That's the setup done, now do the first pair of words.
 # We make an exception and use method (2) on the first two words, to reduce
 # overhead.
	srw 9,9,5
	and 0,7,8
	or 10,7,8
	add 0,0,7
	nor 0,10,0
	and. 8,0,9
	bne done0
 # Handle second word of pair. Put addi between branches to avoid hurting
 # branch prediction.
	addi 6,6,0xfffffeff

	bne 1,loop
	lwzu 8,4(4)
	and 0,7,8
	or 10,7,8
	add 0,0,7
	nor. 0,10,0
	bne done0

 # The loop.

loop:	lwz 8,4(4)
	lwzu 9,8(4)
	add 0,6,8
	nor 10,7,8
	and. 0,0,10
	add 11,6,9
	nor 12,7,9
	bne done1
	and. 0,11,12
	beq loop

	and 0,7,9
	or 10,7,9
	b done2

done1:	addi 4,4,-4
	and 0,7,9
	or 10,7,9
done2:	add 0,0,7
	nor 0,10,0

 # When we get to here, r4 points to the first word in the string that
 # contains a zero byte, and the most significant set bit in r8 is in that
 # byte.
done0:	cntlzw 11,8
	subf 0,3,4
	srwi 11,11,3
	add 3,0,11
	blr
0:
	.size	 strlen,0b-strlen
