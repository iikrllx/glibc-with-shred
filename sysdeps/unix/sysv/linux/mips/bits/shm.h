/* Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, August 1995.

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

#ifndef _SYS_SHM_BUF_H

#define _SYS_SHM_BUF_H	1
#include <features.h>

#include <sys/types.h>

/* Permission flag for shmget.  */
#define SHM_R		0400		/* or S_IRUGO from <linux/stat.h> */
#define SHM_W		0200		/* or S_IWUGO from <linux/stat.h> */

/* Flags for `shmat'.  */
#define SHM_RDONLY	010000		/* attach read-only else read-write */
#define SHM_RND		020000		/* round attach address to SHMLBA */
#define SHM_REMAP	040000		/* take-over region on attach */

/* Commands for `shmctl'.  */
#define SHM_LOCK	11		/* lock segment (root only) */
#define SHM_UNLOCK	12		/* unlock segment (root only) */


__BEGIN_DECLS

/* Data structure describing a set of semaphores.  */
struct shmid_ds
{
  struct ipc_perm shm_perm;		/* operation permission struct */
  int shm_segsz;			/* size of segment in bytes */
  __time_t shm_atime;			/* time of last shmat() */
  __time_t shm_dtime;			/* time of last shmdt() */
  __time_t shm_ctime;			/* time of last change by shmctl() */
  long shm_cpid;			/* pid of creator */
  long shm_lpid;			/* pid of last shmop */
  unsigned short int shm_nattch;	/* number of current attaches */
  unsigned short int __shm_npages;	/* size of segment (pages) */
  unsigned long int *__shm_pages;	/* array of ptrs to frames -> SHMMAX */
  struct vm_area_struct *__attaches;	/* descriptors for attaches */
};

#ifdef __USE_MISC

/* ipcs ctl commands */
#define SHM_STAT 	13
#define SHM_INFO 	14

/* shm_mode upper byte flags */
#define	SHM_DEST	01000	/* segment will be destroyed on last detach */
#define SHM_LOCKED      02000   /* segment will not be swapped */

struct	shminfo
{
  int shmmax;
  int shmmin;
  int shmmni;
  int shmseg;
  int shmall;
};

struct shm_info
{
  int   used_ids;
  ulong shm_tot;	/* total allocated shm */
  ulong shm_rss;	/* total resident shm */
  ulong shm_swp;	/* total swapped shm */
  ulong swap_attempts;
  ulong swap_successes;
};

#endif /* __USE_MISC */

__END_DECLS

#endif /* bits/shm_buf.h */
