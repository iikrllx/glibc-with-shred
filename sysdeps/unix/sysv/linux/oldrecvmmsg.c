/* Compatibility version of recvmsg.
   Copyright (C) 2010-2016 Free Software Foundation, Inc.
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

#include <sys/socket.h>
#include <sysdep-cancel.h>
#include <socketcall.h>
#include <shlib-compat.h>

#if __WORDSIZE == 64
# if SHLIB_COMPAT (libc, GLIBC_2_12, GLIBC_2_24)

/* Do not use the recvmmsg syscall on socketcall architectures unless
   it was added at the same time as the socketcall support or can be
   assumed to be present.  */
#  if defined __ASSUME_SOCKETCALL \
    && !defined __ASSUME_RECVMMSG_SYSCALL_WITH_SOCKETCALL \
    && !defined __ASSUME_RECVMMSG_SYSCALL
#   undef __NR_recvmmsg
#  endif

int
__old_recvmmsg (int fd, struct mmsghdr *vmessages, unsigned int vlen,
		int flags, struct timespec *tmo)
{
#  ifdef __NR_recvmmsg
  return SYSCALL_CANCEL (recvmmsg, fd, vmessages, vlen, flags, tmo);
#  elif defined __NR_socketcall
#   ifdef __ASSUME_RECVMMSG_SOCKETCALL
  return SOCKETCALL_CANCEL (recvmmsg, fd, vmessages, vlen, flags, tmo);
#   else
  static int have_recvmmsg;
  if (__glibc_likely (have_recvmmsg >= 0))
    {
      int ret = SOCKETCALL_CANCEL (recvmmsg, fd, vmessages, vlen, flags,
				   tmo);
      /* The kernel returns -EINVAL for unknown socket operations.
	 We need to convert that error to an ENOSYS error.  */
      if (__builtin_expect (ret < 0, 0)
	  && have_recvmmsg == 0
	  && errno == EINVAL)
	{
	  /* Try another call, this time with an invalid file
	     descriptor and all other parameters cleared.  This call
	     will not cause any harm and it will return
	     immediately.  */
	  ret = SOCKETCALL_CANCEL (invalid, -1);
	  if (errno == EINVAL)
	    {
	      have_recvmmsg = -1;
	      __set_errno (ENOSYS);
	    }
	  else
	    {
	      have_recvmmsg = 1;
	      __set_errno (EINVAL);
	    }
	  return -1;
	}
      return ret;
    }
  __set_errno (ENOSYS);
  return -1;
#   endif /* __ASSUME_RECVMMSG_SOCKETCALL  */
#  else
  __set_errno (ENOSYS);
  return -1;
#  endif
}
compat_symbol (libc, __old_recvmmsg, recvmmsg, GLIBC_2_12);

# endif /* SHLIB_COMPAT (libc, GLIBC_2_12, GLIBC_2_24)  */
#endif /* __WORDSIZE == 64  */
