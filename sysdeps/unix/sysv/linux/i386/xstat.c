/* xstat using old-style Unix stat system call.
   Copyright (C) 1991,95,96,97,98,2000 Free Software Foundation, Inc.
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

/* Ho hum, if xstat == xstat64 we must get rid of the prototype or gcc
   will complain since they don't strictly match.  */
#define __xstat64 __xstat64_disable

#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <kernel_stat.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include <xstatconv.c>

extern int __syscall_stat (const char *, struct kernel_stat *);

#ifdef __NR_stat64
extern int __syscall_stat64 (const char *, struct stat64 *);
# if  __ASSUME_STAT64_SYSCALL == 0
/* The variable is shared between all wrappers around *stat64 calls.  */
extern int __have_no_stat64;
# endif
#endif


/* Get information about the file NAME in BUF.  */
int
__xstat (int vers, const char *name, struct stat *buf)
{
#if __ASSUME_STAT64_SYSCALL > 0
  struct kernel_stat kbuf;
  int result;

  result = INLINE_SYSCALL (stat64, 2, name, &buf64);
  if (result == 0)
    result = xstat32_conv (vers, &buf64, buf);
  return result;
#else
  struct kernel_stat kbuf;
  int result;

  if (vers == _STAT_VER_KERNEL)
    {
      return INLINE_SYSCALL (stat, 2, name, (struct kernel_stat *) buf);
    }
# if defined __NR_stat64
  /* To support 32 bit UIDs, we have to use stat64.  The normal stat call only returns
     16 bit UIDs.  */
  if (! __have_no_stat64)
    {
      struct stat64 buf64;
      
      int saved_errno = errno;
      result = INLINE_SYSCALL (stat64, 2, name, &buf64);

      if (result == 0)
	result = xstat32_conv (vers, &buf64, buf);
      
      if (result != -1 || errno != ENOSYS)
	return result;

      __set_errno (saved_errno);
      __have_no_stat64 = 1;
    }
# endif  
  result = INLINE_SYSCALL (stat, 2, name, &kbuf);
  if (result == 0)
    result = xstat_conv (vers, &kbuf, buf);

  return result;
#endif  /* __ASSUME_STAT64_SYSCALL  */
}

weak_alias (__xstat, _xstat);
#ifdef XSTAT_IS_XSTAT64
#undef __xstat64
strong_alias (__xstat, __xstat64);
#endif
