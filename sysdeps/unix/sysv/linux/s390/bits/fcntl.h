/* O_*, F_*, FD_* bit values for Linux.
   Copyright (C) 2000-2021 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#ifndef	_FCNTL_H
# error "Never use <bits/fcntl.h> directly; include <fcntl.h> instead."
#endif

#include <bits/wordsize.h>

#if __WORDSIZE == 64
/* Not necessary, files are always with 64bit off_t.  */
# define __O_LARGEFILE	0
#endif

#if __WORDSIZE == 64
/* Not necessary, we always have 64-bit offsets.  */
# define F_GETLK64	5	/* Get record locking info.  */
# define F_SETLK64	6	/* Set record locking info (non-blocking).  */
# define F_SETLKW64	7	/* Set record locking info (blocking).	*/
#endif

struct flock
  {
    short int l_type;	/* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.	*/
    short int l_whence;	/* Where `l_start' is relative to (like `lseek').  */
#if __WORDSIZE == 64 || !defined __USE_FILE_OFFSET64
    __off_t l_start;	/* Offset where the lock begins.  */
    __off_t l_len;	/* Size of the locked area; zero means until EOF.  */
#else
    __off64_t l_start;	/* Offset where the lock begins.  */
    __off64_t l_len;	/* Size of the locked area; zero means until EOF.  */
#endif
    __pid_t l_pid;	/* Process holding the lock.  */
  };

#ifdef __USE_LARGEFILE64
struct flock64
  {
    short int l_type;	/* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.	*/
    short int l_whence;	/* Where `l_start' is relative to (like `lseek').  */
    __off64_t l_start;	/* Offset where the lock begins.  */
    __off64_t l_len;	/* Size of the locked area; zero means until EOF.  */
    __pid_t l_pid;	/* Process holding the lock.  */
  };
#endif

#if __WORDSIZE == 64
# define __POSIX_FADV_DONTNEED	6 /* Don't need these pages.  */
# define __POSIX_FADV_NOREUSE	7 /* Data will be accessed once.  */
#else
# define __POSIX_FADV_DONTNEED	4 /* Don't need these pages.  */
# define __POSIX_FADV_NOREUSE	5 /* Data will be accessed once.  */
#endif

/* Include generic Linux declarations.  */
#include <bits/fcntl-linux.h>
