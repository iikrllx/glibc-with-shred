/* Copyright (C) 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jakub Jelinek <jakub@redhat.com>, 1999.

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

#include <errno.h>
#include <unistd.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include <sys/mman.h>

#include <asm/page.h>

#include "kernel-features.h"

#ifdef __NR_mmap2
extern int __syscall_mmap2(__ptr_t, size_t, int, int, int, off_t);
#ifndef __ASSUME_MMAP2_SYSCALL
static int have_no_mmap2;
#endif
#endif

__ptr_t
__mmap64 (__ptr_t addr, size_t len, int prot, int flags, int fd, off64_t offset)
{
#ifdef __NR_mmap2
  if (
#ifndef __ASSUME_MMAP2_SYSCALL
      ! have_no_mmap2 &&
#endif
      ! (offset & PAGE_MASK))
    {
#ifndef __ASSUME_MMAP2_SYSCALL
      int saved_errno = errno;
#endif
      /* This will be always 12, no matter what page size is.  */
      __ptr_t result = INLINE_SYSCALL (mmap2, 6, addr, len, prot, flags,
				   fd, (off_t) (offset >> PAGE_SHIFT));

#ifndef __ASSUME_MMAP2_SYSCALL
      if (result != (__ptr_t) -1 || errno != ENOSYS)
#endif
	return result;

#ifndef __ASSUME_MMAP2_SYSCALL
      __set_errno (saved_errno);
      have_no_mmap2 = 1;
#endif
    }
#endif
  if (offset != (off_t) offset || (offset + len) != (off_t) (offset + len))
    {
      __set_errno (EINVAL);
      return MAP_FAILED;
    }

  return __mmap (addr, len, prot, flags, fd, (off_t) offset);
}

weak_alias (__mmap64, mmap64)
