/* Copyright (C) 1992, 1996, 1997 Free Software Foundation, Inc.
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
 *	X/Open Portability Guide 4.2: ftw.h
 */

#ifndef _FTW_H

#define	_FTW_H	1
#include <features.h>

#include <sys/types.h>
#include <statbuf.h>


__BEGIN_DECLS

/* Values for the FLAG argument to the user function passed to `ftw'
   and 'nftw'.  */
enum
{
  FTW_F,		/* Regular file.  */
#define FTW_F	 FTW_F
  FTW_D,		/* Directory.  */
#define FTW_D	 FTW_D
  FTW_DNR,		/* Unreadable directory.  */
#define FTW_DNR	 FTW_DNR
  FTW_NS,		/* Unstatable file.  */
#define FTW_NS	 FTW_NS

#ifdef __USE_XOPEN_EXTENDED

  FTW_SL,		/* Symbolic link.  */
# define FTW_SL	 FTW_SL

/* These flags are only passed from the `nftw' function.  */
  FTW_DP,		/* Directory, all subdirs have been visited. */
# define FTW_DP	 FTW_DP
  FTW_SLN		/* Symbolic link naming non-existing file.  */
# define FTW_SLN FTW_SLN

#endif	/* extended X/Open */
};


#ifdef __USE_XOPEN_EXTENDED
/* Flags for fourth argument of `nftw'.  */
enum
{
  FTW_PHYS = 1,		/* Perform physical walk, ignore symlinks.  */
# define FTW_PHYS	FTW_PHYS
  FTW_MOUNT = 2,	/* Report only files on same file system as the
			   argument.  */
# define FTW_MOUNT	FTW_MOUNT
  FTW_CHDIR = 4,	/* Change to current directory while processing it.  */
# define FTW_CHDIR	FTW_CHDIR
  FTW_DEPTH = 8		/* Report files in directory before directory itself.*/
# define FTW_DEPTH	FTW_DEPTH
};

/* Structure used for fourth argument to callback function for `nftw'.  */
struct FTW
  {
    int base;
    int level;
  };
#endif	/* extended X/Open */


/* Convenient types for callback functions.  */
typedef int (*__ftw_func_t) __P ((__const char *filename,
				  __const struct stat *status, int flag));
#ifdef __USE_XOPEN_EXTENDED
typedef int (*__nftw_func_t) __P ((__const char *filename,
				   __const struct stat *status, int flag,
				   struct FTW *));
#endif

/* Call a function on every element in a directory tree.  */
extern int ftw __P ((__const char *dir, __ftw_func_t func, int descriptors));

#ifdef __USE_XOPEN_EXTENDED
/* Call a function on every element in a directory tree.  FLAG allows
   to specify the behaviour more detailed.  */
extern int nftw __P ((__const char *dir, __nftw_func_t func,
		      int descriptors, int flag));
#endif

__END_DECLS

#endif	/* ftw.h */
