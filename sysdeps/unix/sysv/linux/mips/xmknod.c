/* xmknod call using old-style Unix mknod system call.
   Copyright (C) 1991, 93, 95, 96, 97, 98 Free Software Foundation, Inc.
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

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <sysdep.h>
#include <sys/syscall.h>

extern int __syscall_mknod (const char *, unsigned long, unsigned int);

/* Create a device file named PATH, with permission and special bits MODE
   and device number DEV (which can be constructed from major and minor
   device numbers with the `makedev' macro above).  */
int
__xmknod (int vers, const char *path, mode_t mode, dev_t *dev)
{
  unsigned long k_dev;

  if (vers != _MKNOD_VER)
    {
      __set_errno (EINVAL);
      return -1;
    }

  /* We must convert the value to dev_t type used by the kernel.  */
  k_dev = ((major (*dev) & 0xff) << 8) | (minor (*dev) & 0xff);

  return INLINE_SYSCALL (mknod, 3, path, mode, k_dev);
}

weak_alias (__xmknod, _xmknod)
