/* Copyright (C) 1991-2015 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <sysdeps/generic/sysdep.h>

#include <sys/syscall.h>
#define	HAVE_SYSCALLS

/* Note that using a `PASTE' macro loses.  */
#define	SYSCALL__(name, args)	PSEUDO (__##name, name, args)
#define	SYSCALL(name, args)	PSEUDO (name, name, args)

/* Cancellation macros.  */
#define __SYSCALL_NARGS_X(a,b,c,d,e,f,g,n,...) n
#define __SYSCALL_NARGS(...) \
  __SYSCALL_NARGS_X (__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0,)

#define SYSCALL_CANCEL(name, ...) \
  ({									     \
    long int sc_ret;							     \
    if (SINGLE_THREAD_P) 						     \
      sc_ret = INLINE_SYSCALL (name, __SYSCALL_NARGS(__VA_ARGS__),	     \
			       __VA_ARGS__);				     \
    else								     \
      {									     \
	int sc_cancel_oldtype = LIBC_CANCEL_ASYNC ();			     \
	sc_ret = INLINE_SYSCALL (name, __SYSCALL_NARGS (__VA_ARGS__),	     \
				 __VA_ARGS__);				     \
        LIBC_CANCEL_RESET (sc_cancel_oldtype);				     \
      }									     \
    sc_ret;								     \
  })

/* Machine-dependent sysdep.h files are expected to define the macro
   PSEUDO (function_name, syscall_name) to emit assembly code to define the
   C-callable function FUNCTION_NAME to do system call SYSCALL_NAME.
   r0 and r1 are the system call outputs.  MOVE(x, y) should be defined as
   an instruction such that "MOVE(r1, r0)" works.  ret should be defined
   as the return instruction.  */

#ifndef SYS_ify
#define SYS_ify(syscall_name) SYS_##syscall_name
#endif

/* Terminate a system call named SYM.  This is used on some platforms
   to generate correct debugging information.  */
#ifndef PSEUDO_END
#define PSEUDO_END(sym)
#endif
#ifndef PSEUDO_END_NOERRNO
#define PSEUDO_END_NOERRNO(sym)	PSEUDO_END(sym)
#endif
#ifndef PSEUDO_END_ERRVAL
#define PSEUDO_END_ERRVAL(sym)	PSEUDO_END(sym)
#endif

/* Wrappers around system calls should normally inline the system call code.
   But sometimes it is not possible or implemented and we use this code.  */
#ifndef INLINE_SYSCALL
#define INLINE_SYSCALL(name, nr, args...) __syscall_##name (args)
#endif

/* Similar to INLINE_SYSCALL, but with return type.  It should only be
   used with function return.  */
#ifndef INLINE_SYSCALL_RETURN
#define INLINE_SYSCALL_RETURN(name, nr, type, args...) \
  INLINE_SYSCALL (name, nr, args)
#endif

/* Set error number and return value.  It should only be used with
   function return.  ERR is the negative error number returned from
   the majority of Linux kernels for which -ERR is no-op
   with INTERNAL_SYSCALL_ERRNO.   */
#ifndef INLINE_SYSCALL_ERROR_RETURN
#define INLINE_SYSCALL_ERROR_RETURN(err, type, value) \
  ({								\
    __set_errno (-err);						\
    (type) (value);						\
  })
#endif
