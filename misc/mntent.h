/* Utilities for reading/writing fstab, mtab, etc.
   Copyright (C) 1995, 1996, 1997, 1998 Free Software Foundation, Inc.
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

#ifndef	_MNTENT_H
#define	_MNTENT_H	1

#include <features.h>
#define __need_FILE
#include <stdio.h>
#include <paths.h>


/* File listing canonical interesting mount points.  */
#define	MNTTAB		_PATH_MNTTAB	/* Deprecated alias.  */

/* File listing currently active mount points.  */
#define	MOUNTED		_PATH_MOUNTED	/* Deprecated alias.  */


/* General filesystem types.  */
#define MNTTYPE_IGNORE	"ignore"	/* Ignore this entry.  */
#define MNTTYPE_NFS	"nfs"		/* Network file system.  */
#define MNTTYPE_SWAP	"swap"		/* Swap device.  */


/* Generic mount options.  */
#define MNTOPT_DEFAULTS	"defaults"	/* Use all default options.  */
#define MNTOPT_RO	"ro"		/* Read only.  */
#define MNTOPT_RW	"rw"		/* Read/write.  */
#define MNTOPT_SUID	"suid"		/* Set uid allowed.  */
#define MNTOPT_NOSUID	"nosuid"	/* No set uid allowed.  */
#define MNTOPT_NOAUTO	"noauto"	/* Do not auto mount.  */


__BEGIN_DECLS

/* Structure describing a mount table entry.  */
struct mntent
  {
    const char *mnt_fsname;	/* Device or server for filesystem.  */
    const char *mnt_dir;	/* Directory mounted on.  */
    const char *mnt_type;	/* Type of filesystem: ufs, nfs, etc.  */
    const char *mnt_opts;	/* Comma-separated options for fs.  */
    int mnt_freq;		/* Dump frequency (in days).  */
    int mnt_passno;		/* Pass number for `fsck'.  */
  };


/* Prepare to begin reading and/or writing mount table entries from the
   beginning of FILE.  MODE is as for `fopen'.  */
extern FILE *__setmntent __P ((__const char *__file, __const char *__mode));
extern FILE *setmntent __P ((__const char *__file, __const char *__mode));

/* Read one mount table entry from STREAM.  Returns a pointer to storage
   reused on the next call, or null for EOF or error (use feof/ferror to
   check).  */
extern struct mntent *getmntent __P ((FILE *__stream));

#ifdef __USE_MISC
/* Reentrant version of the above function.  */
extern struct mntent *__getmntent_r __P ((FILE *__stream,
					  struct mntent *__result,
					  char *__buffer, int __bufsize));
extern struct mntent *getmntent_r __P ((FILE *__stream,
					struct mntent *__result,
					char *__buffer, int __bufsize));
#endif

/* Write the mount table entry described by MNT to STREAM.
   Return zero on success, nonzero on failure.  */
extern int __addmntent __P ((FILE *__stream, __const struct mntent *__mnt));
extern int addmntent __P ((FILE *__stream, __const struct mntent *__mnt));

/* Close a stream opened with `setmntent'.  */
extern int __endmntent __P ((FILE *__stream));
extern int endmntent __P ((FILE *__stream));

/* Search MNT->mnt_opts for an option matching OPT.
   Returns the address of the substring, or null if none found.  */
extern char *__hasmntopt __P ((__const struct mntent *__mnt,
			       __const char *__opt));
extern char *hasmntopt __P ((__const struct mntent *__mnt,
			     __const char *__opt));


__END_DECLS

#endif	/* mntent.h */
