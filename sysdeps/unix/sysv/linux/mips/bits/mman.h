/* Definitions for POSIX memory map interface.  Linux/MIPS version.
   Copyright (C) 1997, 2000 Free Software Foundation, Inc.
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

#ifndef _SYS_MMAN_H
# error "Never use <bits/mman.h> directly; include <sys/mman.h> instead."
#endif

/* The following definitions basically come from the kernel headers.
   But the kernel header is not namespace clean.  */


/* Protections are chosen from these bits, OR'd together.  The
   implementation does not necessarily support PROT_EXEC or PROT_WRITE
   without PROT_READ.  The only guarantees are that no writing will be
   allowed without PROT_WRITE and no access will be allowed for PROT_NONE. */

#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */
#define PROT_EXEC	0x4		/* Page can be executed.  */
#define PROT_NONE	0x0		/* Page can not be accessed.  */

/* Sharing types (must choose one and only one of these).  */
#define MAP_SHARED	0x01		/* Share changes.  */
#define MAP_PRIVATE	0x02		/* Changes are private.  */
#ifdef __USE_MISC
# define MAP_TYPE	0x0f		/* Mask for type of mapping.  */
#endif

/* Other flags.  */
#define MAP_FIXED	0x10		/* Interpret addr exactly.  */
#ifdef __USE_MISC
# define MAP_FILE	0x00
# define MAP_ANONYMOUS	0x0800		/* Don't use a file.  */
# define MAP_ANON	MAP_ANONYMOUS
# define MAP_RENAME	MAP_ANONYMOUS
#endif

/* These are Linux-specific.  */
#ifdef __USE_MISC
# define MAP_NORESERVE	0x0400		/* don't check for reservations */
# define MAP_ANONYMOUS	0x0800		/* don't use a file */
# define MAP_GROWSDOWN	0x1000		/* stack-like segment */
# define MAP_DENYWRITE	0x2000		/* ETXTBSY */
# define MAP_EXECUTABLE	0x4000		/* mark it as an executable */
# define MAP_LOCKED	0x8000		/* pages are locked */
#endif

/* Flags to `msync'.  */
#define MS_ASYNC	1		/* Sync memory asynchronously.  */
#define MS_INVALIDATE	2		/* Invalidate the caches.  */
#define MS_SYNC		4		/* Synchronous memory sync.  */

/* Flags for `mlockall'.  */
#define MCL_CURRENT	1		/* Lock all currently mapped pages.  */
#define MCL_FUTURE	2		/* Lock all additions to address
					   space.  */

/* Advice to `madvise'.  */
#ifdef __USE_BSD
#define MADV_NORMAL	0		/* default page-in behavior */
#define MADV_RANDOM	1		/* page-in minimum required */
#define MADV_SEQUENTIAL	2		/* read-ahead aggressively */
#define MADV_WILLNEED	3		/* pre-fault pages */
#define MADV_DONTNEED	4		/* discard these pages */
#endif

/* Flags for `mremap'.  */
#ifdef __USE_GNU
# define MREMAP_MAYMOVE	1
#endif
