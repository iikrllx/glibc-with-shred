/* Copyright (C) 2000, 2002, 2003 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _LINUX_MIPS_SYSDEP_H
#define _LINUX_MIPS_SYSDEP_H 1

/* There is some commonality.  */
#include <sysdeps/unix/mips/mips64/n64/sysdep.h>

/* For Linux we can use the system call table in the header file
	/usr/include/asm/unistd.h
   of the kernel.  But these symbols do not follow the SYS_* syntax
   so we have to redefine the `SYS_ify' macro here.  */
#undef SYS_ify
#ifdef __STDC__
# define SYS_ify(syscall_name)	__NR_N64_##syscall_name
#else
# define SYS_ify(syscall_name)	__NR_N64_/**/syscall_name
#endif


#ifndef __ASSEMBLER__
#if 0 /* untested */
/* Define a macro which expands into the inline wrapper code for a system
   call.  */
#undef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...)                               \
  ({ INTERNAL_SYSCALL_DECL(err);					\
     long result_var = INTERNAL_SYSCALL (name, err, nr, args);      	\
     if ( INTERNAL_SYSCALL_ERROR_P (result_var, err) )  		\
       {                                                                \
         __set_errno (INTERNAL_SYSCALL_ERRNO (result_var, err));      	\
         result_var = -1L;                               		\
       }                                                                \
     result_var; })

#undef INTERNAL_SYSCALL_DECL
#define INTERNAL_SYSCALL_DECL(err) long err

#undef INTERNAL_SYSCALL_ERROR_P
#define INTERNAL_SYSCALL_ERROR_P(val, err)   ((long) (err))

#undef INTERNAL_SYSCALL_ERRNO
#define INTERNAL_SYSCALL_ERRNO(val, err)     (val)

#undef INTERNAL_SYSCALL
#define INTERNAL_SYSCALL(name, err, nr, args...) internal_syscall##nr(name, err, args)

#define internal_syscall0(name, err, dummy...) 				\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a3 asm("$7"); 					\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %2\t\t\t# " #name "\n\t"				\
	"syscall\n\t" 							\
	".set reorder" 							\
	: "=r" (__v0), "=r" (__a3) 					\
	: "i" (SYS_ify(name))						\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall1(name, err, arg1) 				\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a3 asm("$7"); 					\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %3\t\t\t# " #name "\n\t"				\
	"syscall\n\t" 							\
	".set reorder" 							\
	: "=r" (__v0), "=r" (__a3) 					\
	: "r" (__a0), "i" (SYS_ify(name)) 				\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall2(name, err, arg1, arg2) 			\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a1 asm("$5") = (long) arg2; 			\
	register long __a3 asm("$7"); 					\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %4\t\t\t# " #name "\n\t" 				\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "=r" (__a3) 					\
	: "r" (__a0), "r" (__a1), "i" (SYS_ify(name))			\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall3(name, err, arg1, arg2, arg3) 			\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a1 asm("$5") = (long) arg2; 			\
	register long __a2 asm("$6") = (long) arg3; 			\
	register long __a3 asm("$7"); 					\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %5\t\t\t# " #name "\n\t" 				\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "=r" (__a3) 					\
	: "r" (__a0), "r" (__a1), "r" (__a2), "i" (SYS_ify(name)) 	\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall4(name, err, arg1, arg2, arg3, arg4) 		\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a1 asm("$5") = (long) arg2; 			\
	register long __a2 asm("$6") = (long) arg3; 			\
	register long __a3 asm("$7") = (long) arg4; 			\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %5\t\t\t# " #name "\n\t" 				\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "+r" (__a3) 					\
	: "r" (__a0), "r" (__a1), "r" (__a2), "i" (SYS_ify(name)) 	\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall5(name, err, arg1, arg2, arg3, arg4, arg5) 	\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a1 asm("$5") = (long) arg2; 			\
	register long __a2 asm("$6") = (long) arg3; 			\
	register long __a3 asm("$7") = (long) arg4; 			\
	register long __a4 asm("$8") = (long) arg5; 			\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %5\t\t\t# " #name "\n\t" 				\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "+r" (__a3) 					\
	: "r" (__a0), "r" (__a1), "r" (__a2), "i" (SYS_ify(name)), 	\
	  "r" (__a4) 							\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall6(name, err, arg1, arg2, arg3, arg4, arg5, arg6)\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a1 asm("$5") = (long) arg2; 			\
	register long __a2 asm("$6") = (long) arg3; 			\
	register long __a3 asm("$7") = (long) arg4; 			\
	register long __a4 asm("$8") = (long) arg5; 			\
	register long __a5 asm("$9") = (long) arg6; 			\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %5\t\t\t# " #name "\n\t" 				\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "+r" (__a3) 					\
	: "r" (__a0), "r" (__a1), "r" (__a2), "i" (SYS_ify(name)), 	\
	  "r" (__a4), "r" (__a5)					\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define internal_syscall7(name, err, arg1, arg2, arg3, arg4, arg5, arg6, arg7)\
({ 									\
	long _sys_result;						\
									\
	{								\
	register long __v0 asm("$2"); 					\
	register long __a0 asm("$4") = (long) arg1; 			\
	register long __a1 asm("$5") = (long) arg2; 			\
	register long __a2 asm("$6") = (long) arg3; 			\
	register long __a3 asm("$7") = (long) arg4; 			\
	register long __a4 asm("$8") = (long) arg5; 			\
	register long __a5 asm("$9") = (long) arg6; 			\
	register long __a6 asm("$10") = (long) arg7; 			\
	__asm__ volatile ( 						\
	".set\tnoreorder\n\t" 						\
	"li\t$2, %5\t\t\t# " #name "\n\t" 				\
	"syscall\n\t" 							\
	".set\treorder" 						\
	: "=r" (__v0), "+r" (__a3) 					\
	: "r" (__a0), "r" (__a1), "r" (__a2), "i" (SYS_ify(name)), 	\
	  "r" (__a4), "r" (__a5), "r" (__a6)				\
	: __SYSCALL_CLOBBERS); 						\
	err = __a3;							\
	_sys_result = __v0;						\
	}								\
	_sys_result;							\
})

#define __SYSCALL_CLOBBERS "$1", "$3", "$11", "$12", "$13", "$14", "$15", "$24", "$25"
#endif /* untested */
#endif /* __ASSEMBLER__ */

#endif /* linux/mips/sysdep.h */
