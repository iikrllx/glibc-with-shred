/* Atomic operations.  PowerPC64 version.
   Copyright (C) 2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Paul Mackerras <paulus@au.ibm.com>, 2003.

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

/*
 * The 32-bit exchange_bool is different on powerpc64 because the subf
 * does signed 64-bit arthmatic while the lwarx is 32-bit unsigned
 * (a load word and zero (high 32) form) load.
 * In powerpc64 register values are 64-bit by default,  including oldval.
 * Net we need to extend sign word the result of lwarx to 64-bit so the
 * 64-bit subtract from gives the expected result and sets the condition
 * correctly.
 */
# define __arch_compare_and_exchange_bool_32_acq(mem, newval, oldval) \
({									      \
  unsigned int __tmp;							      \
  __asm __volatile (__ARCH_REL_INSTR "\n"				      \
		    "1:	lwarx	%0,0,%1\n"				      \
		    "	extsw	%0,%0\n"				      \
		    "	subf.	%0,%2,%0\n"				      \
		    "	bne	2f\n"					      \
		    "	stwcx.	%3,0,%1\n"				      \
		    "	bne-	1b\n"					      \
		    "2:	" __ARCH_ACQ_INSTR				      \
		    : "=&r" (__tmp)					      \
		    : "b" (mem), "r" (oldval), "r" (newval)		      \
		    : "cr0", "memory");					      \
  __tmp != 0;								      \
})

/* 
 * Only powerpc64 processors support Load doubleword and reserve index (ldarx) 
 * and Store doubleword conditional indexed (stdcx) instructions.  So here
 * we define the 64-bit forms.
 */
# define __arch_compare_and_exchange_bool_64_acq(mem, newval, oldval) \
({									      \
  unsigned long	__tmp;							      \
  __asm __volatile (__ARCH_REL_INSTR "\n"				      \
		    "1:	ldarx	%0,0,%1\n"				      \
		    "	subf.	%0,%2,%0\n"				      \
		    "	bne	2f\n"					      \
		    "	stdcx.	%3,0,%1\n"				      \
		    "	bne-	1b\n"					      \
		    "2:	" __ARCH_ACQ_INSTR				      \
		    : "=&r" (__tmp)					      \
		    : "b" (mem), "r" (oldval), "r" (newval)		      \
		    : "cr0", "memory");					      \
  __tmp != 0;								      \
})

#define __arch_compare_and_exchange_val_64_acq(mem, newval, oldval) \
  ({									      \
      __typeof (*(mem)) __tmp;						      \
      __typeof (mem)  __memp = (mem);					      \
      __asm __volatile (__ARCH_REL_INSTR "\n"				      \
		        "1:	ldarx	%0,0,%1\n"			      \
		        "	cmpd	%0,%2\n"			      \
		        "	bne	2f\n"				      \
		        "	stdcx.	%3,0,%1\n"			      \
		        "	bne-	1b\n"				      \
		        "2:	" __ARCH_ACQ_INSTR			      \
		        : "=&r" (__tmp)					      \
		        : "b" (__memp), "r" (oldval), "r" (newval)	      \
		        : "cr0", "memory");				      \
      __tmp;								      \
  })

# define __arch_atomic_exchange_64(mem, value) \
    ({									      \
      __typeof (*mem) __val;						      \
      __asm __volatile (__ARCH_REL_INSTR "\n"				      \
			"1:	ldarx	%0,0,%2\n"			      \
			"	stdcx.	%3,0,%2\n"			      \
			"	bne-	1b"				      \
			: "=&r" (__val), "=m" (*mem)			      \
			: "b" (mem), "r" (value), "1" (*mem)		      \
			: "cr0");					      \
      __val;								      \
    })

# define __arch_atomic_exchange_and_add_64(mem, value) \
    ({									      \
      __typeof (*mem) __val, __tmp;					      \
      __asm __volatile ("1:	ldarx	%0,0,%3\n"			      \
			"	add	%1,%0,%4\n"			      \
			"	stdcx.	%1,0,%3\n"			      \
			"	bne-	1b"				      \
			: "=&b" (__val), "=&r" (__tmp), "=m" (*mem)	      \
			: "b" (mem), "r" (value), "2" (*mem)		      \
			: "cr0");					      \
      __val;								      \
    })

# define __arch_atomic_decrement_if_positive_64(mem) \
  ({ int __val, __tmp;							      \
     __asm __volatile ("1:	ldarx	%0,0,%3\n"			      \
		       "	cmpdi	0,%0,0\n"			      \
		       "	addi	%1,%0,-1\n"			      \
		       "	ble	2f\n"				      \
		       "	stdcx.	%1,0,%3\n"			      \
		       "	bne-	1b\n"				      \
		       "2:	" __ARCH_ACQ_INSTR			      \
		       : "=&b" (__val), "=&r" (__tmp), "=m" (*mem)	      \
		       : "b" (mem), "2" (*mem)				      \
		       : "cr0");					      \
     __val;								      \
  })

/* 
 * All powerpc64 processors support the new "light weight"  sync (lwsync).   
 */
# define atomic_read_barrier()	__asm ("lwsync" ::: "memory")

/*
 * Include the rest of the atomic ops macros which are common to both
 * powerpc32 and powerpc64. 
 */
#include_next <bits/atomic.h>
