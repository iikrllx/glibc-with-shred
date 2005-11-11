/* Copyright (C) 2005 Free Software Foundation, Inc.
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
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <kernel_stat.h>

#include <sysdep.h>
#include <sys/syscall.h>
#include <bp-checks.h>

#include "kernel-features.h"

#if __ASSUME_STAT64_SYSCALL == 0
# include <xstatconv.h>
#endif

#ifdef __NR_stat64
# if  __ASSUME_STAT64_SYSCALL == 0
/* The variable is shared between all wrappers around *stat64 calls.
   This is the definition.  */
extern int __have_no_stat64;
# endif
#endif

/* Get information about the file NAME in BUF.  */

int
__fxstatat64 (int vers, int fd, const char *file, struct stat64 *st, int flag)
{
  if (flag & ~AT_SYMLINK_NOFOLLOW)
    {
      __set_errno (EINVAL);
      return -1;
    }

  char *buf = NULL;

  if (fd != AT_FDCWD && file[0] != '/')
    {
      size_t filelen = strlen (file);
      static const char procfd[] = "/proc/self/fd/%d/%s";
      /* Buffer for the path name we are going to use.  It consists of
	 - the string /proc/self/fd/
	 - the file descriptor number
	 - the file name provided.
	 The final NUL is included in the sizeof.   A bit of overhead
	 due to the format elements compensates for possible negative
	 numbers.  */
      size_t buflen = sizeof (procfd) + sizeof (int) * 3 + filelen;
      buf = alloca (buflen);

      __snprintf (buf, buflen, procfd, fd, file);
      file = buf;
    }

  int result;
  INTERNAL_SYSCALL_DECL (err);

#if __ASSUME_STAT64_SYSCALL > 0
  if (flag & AT_SYMLINK_NOFOLLOW)
    result = INTERNAL_SYSCALL (lstat64, err, 2, CHECK_STRING (file),
			       CHECK_1 (st));
  else
    result = INTERNAL_SYSCALL (stat64, err, 2, CHECK_STRING (file),
			       CHECK_1 (st));
  if (__builtin_expect (!INTERNAL_SYSCALL_ERROR_P (result, err), 1))
    {
# if defined _HAVE_STAT64___ST_INO && __ASSUME_ST_INO_64_BIT == 0
      if (st->__st_ino != (__ino_t) st->st_ino)
	st->st_ino = st->__st_ino;
# endif
      return result;
    }
#else
  struct kernel_stat kst;
# if defined __NR_stat64
  if (! __have_no_stat64)
    {
      if (flag & AT_SYMLINK_NOFOLLOW)
	result = INTERNAL_SYSCALL (lstat64, err, 2, CHECK_STRING (file),
				   CHECK_1 (st));
      else
	result = INTERNAL_SYSCALL (stat64, err, 2, CHECK_STRING (file),
				   CHECK_1 (st));

      if (__builtin_expect (!INTERNAL_SYSCALL_ERROR_P (result, err), 1))
	{
#  if defined _HAVE_STAT64___ST_INO && __ASSUME_ST_INO_64_BIT == 0
	  if (st->__st_ino != (__ino_t) st->st_ino)
	    st->st_ino = st->__st_ino;
#  endif
	  return result;
	}
      if (INTERNAL_SYSCALL_ERRNO (result, err) != ENOSYS)
	goto fail;

      __have_no_stat64 = 1;
    }
# endif

  if (flag & AT_SYMLINK_NOFOLLOW)
    result = INTERNAL_SYSCALL (lstat, err, 2, CHECK_STRING (file),
			       __ptrvalue (&kst));
  else
    result = INTERNAL_SYSCALL (stat, err, 2, CHECK_STRING (file),
			       __ptrvalue (&kst));

  if (__builtin_expect (!INTERNAL_SYSCALL_ERROR_P (result, err), 1))
    return __xstat64_conv (vers, &kst, st);

 fail:
  __atfct_seterrno (INTERNAL_SYSCALL_ERRNO (result, err), fd, buf);

  return -1;
#endif
}
