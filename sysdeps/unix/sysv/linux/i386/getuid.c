/* Copyright (C) 2000 Free Software Foundation, Inc.
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

#include <errno.h>
#include <unistd.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include "kernel-features.h"

extern int __syscall_getuid (void);

#ifdef __NR_getuid32
extern int __syscall_getuid32 (void);
# if __ASSUME_32BITUIDS == 0
/* This variable is shared with all files that need to check for 32bit
   uids.  This is the definition.
   -1 if libc does not know yet whether kernel has 32bit uids or not.
   0 if it does have them.
   1 if it does not have them.  */
int __libc_missing_32bit_uids = -1;
# endif
#endif /* __NR_getuid32 */

uid_t
__getuid (void)
{
#if __ASSUME_32BITUIDS > 0
  return INLINE_SYSCALL (getuid32, 0);
#else
# ifdef __NR_getuid32
  if (__libc_missing_32bit_uids <= 0)
    {
      int result;
      int saved_errno = errno;

      result = INLINE_SYSCALL (getuid32, 0);
      if (result == 0 || errno != ENOSYS)
	return result;

      __set_errno (saved_errno);
      __libc_missing_32bit_uids = 1;
    }
# endif /* __NR_getuid32 */

  return INLINE_SYSCALL (getuid, 0);
#endif
}

weak_alias (__getuid, getuid)
