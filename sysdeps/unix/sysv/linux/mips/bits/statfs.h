/* Copyright (C) 1997 Free Software Foundation, Inc.
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

#ifndef _SYS_STATFS_H
# error "Never include <bits/statfs.h> directly; use <sys/statfs.h> instead."
#endif

#include <bits/types.h>  /* for __fsid_t and __fsblkcnt_t*/

struct statfs
  {
    long int f_type;
#define f_fstyp f_type
    long int f_bsize;
    long int f_frsize;	/* Fragment size - unsupported */
#ifndef __USE_FILE_OFFSET64
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_files;
    __fsblkcnt_t f_ffree;
    __fsblkcnt_t f_bavail;
#else
    __fsblkcnt64_t f_blocks;
    __fsblkcnt64_t f_bfree;
    __fsblkcnt64_t f_files;
    __fsblkcnt64_t f_ffree;
    __fsblkcnt64_t f_bavail;
#endif

	/* Linux specials */
    __fsid_t f_fsid;
    long int f_namelen;
    long int f_spare[6];
  };

#ifdef __USE_LARGEFILE64
struct statfs64
  {
    long int f_type;
#define f_fstyp f_type
    long int f_bsize;
    long int f_frsize;	/* Fragment size - unsupported */
    __fsblkcnt64_t f_blocks;
    __fsblkcnt64_t f_bfree;
    __fsblkcnt64_t f_files;
    __fsblkcnt64_t f_ffree;
    __fsblkcnt64_t f_bavail;

	/* Linux specials */
    __fsid_t f_fsid;
    long int f_namelen;
    long int f_spare[6];
  };
#endif
