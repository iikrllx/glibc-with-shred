/* Definition of `struct statvfs', information about a filesystem.
   Copyright (C) 1998 Free Software Foundation, Inc.
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

#ifndef _SYS_STATVFS_H
# error "Never include <bits/statvfs.h> directly; use <sys/statvfs.h> instead."
#endif

#include <bits/types.h>

/* GNU Hurd NOTE: This structure is carefully laid out such that we
   can use the `file_statfs' RPC to implement `statvfs' and
   `fstatvfs'.  Please keep this file in sync with <bits/statfs.h>,
   and pay attention to the note in that file.  */

struct statvfs
  {
    unsigned int __f_type;
    unsigned int f_bsize;
#ifndef __USE_FILE_OFFSET64
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsfilcnt_t f_files;
    __fsfilcnt_t f_ffree;
#else
    __fsblkcnt64_t f_blocks;
    __fsblkcnt64_t f_bfree;
    __fsblkcnt64_t f_bavail;
    __fsfilcnt64_t f_files;
    __fsfilcnt64_t f_ffree;
#endif
    __fsid_t f_fsid;
    unsigned int f_namemax;	/* NOTE: f_namelen in `struct statfs'.  */
#ifndef __USE_FILE_OFFSET64
    __fsfilcnt_t f_favail;
#else
    __fsfilcnt64_t f_favail;
#endif
    unsigned int f_frsize;
    unsigned int f_flag;
    unsigned int f_spare[3];
  };

#ifdef __USE_LARGEFILE64
struct statvfs64
  {
    unsigned int __f_type;
    unsigned int f_bsize;
    __fsblkcnt64_t f_blocks;
    __fsblkcnt64_t f_bfree;
    __fsblkcnt64_t f_bavail;
    __fsfilcnt64_t f_files;
    __fsfilcnt64_t f_ffree;
    __fsid_t f_fsid;
    unsigned int f_namemax;
    __fsfilcnt64_t f_favail;
    unsigned int f_frsize;
    unsigned int f_flag;
    unsigned int f_spare[3];
  };
#endif

/* Definitions for the flag in `f_flag'.
   The values for the non-standard flags come from Linux.  */
enum
{
  ST_RDONLY = 1,
#define ST_RDONLY	ST_RDONLY
  ST_NOSUID = 2,
#define ST_NOSUID	ST_NOSUID
  ST_NOEXEC = 8,
#define ST_NOEXEC	ST_NOEXEC
  ST_SYNCHRONOUS = 16
#define ST_SYNCHRONOUS	ST_SYNCHRONOUS
};
