/* Definition of `struct statfs', information about a filesystem.
   Copyright (C) 1996, 1997 Free Software Foundation, Inc.
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

/*
 * Never include this file directly; use <sys/statfs.h> instead.
 */

#ifndef	_BITS_STATFS_H
#define	_BITS_STATFS_H	1

#include <bits/types.h>

/* GNU Hurd NOTE: The size of this structure (16 ints) is known in
   <hurd/hurd_types.defs>, since it is used in the `file_statfs' RPC.  MiG
   does not cope at all well with the passed C structure not being of the
   expected size.  There are some filler words at the end to allow for
   future expansion.  To increase the size of the structure used in the RPC
   and retain binary compatibility, we would need to assign a new message
   number.  */

struct statfs
  {
    unsigned int f_type;
    unsigned int f_bsize;
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsblkcnt_t f_files;
    __fsblkcnt_t f_ffree;
    __fsid_t f_fsid;
    unsigned int f_namelen;
    unsigned int f_spare[6];
  };


#endif /* bits/statfs.h */
