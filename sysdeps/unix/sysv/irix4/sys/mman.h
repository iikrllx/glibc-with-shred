/* Definitions for BSD-style memory management.  Irix 4 version.
Copyright (C) 1994, 1995, 1996 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifndef	_SYS_MMAN_H

#define	_SYS_MMAN_H	1
#include <features.h>

#include <gnu/types.h>
#define __need_size_t
#include <stddef.h>


/* Protections are chosen from these bits, OR'd together.  The
   implementation does not necessarily support PROT_EXEC or PROT_WRITE
   without PROT_READ.  The only guarantees are that no writing will be
   allowed without PROT_WRITE and no access will be allowed for PROT_NONE. */

#define	PROT_NONE	0x00	/* No access.  */
#define	PROT_READ	0x04	/* Pages can be read.  */
#define	PROT_WRITE	0x02	/* Pages can be written.  */
#define	PROT_EXEC	0x01	/* Pages can be executed.  */
#define	PROT_EXECUTE	PROT_EXEC


/* Sharing types (must choose one and only one of these).  */
#define	MAP_SHARED	0x01	/* Share changes.  */
#define	MAP_PRIVATE	0x02	/* Changes private; copy pages on write.  */
#define	MAP_TYPE	0x0f	/* Mask for sharing type.  */

/* Other flags.  */
#define	MAP_FIXED	0x10	/* Map address must be exactly as requested. */
#define	MAP_RENAME	0x20	/* Rename private pages to file.  */
#define	MAP_AUTOGROW	0x40	/* Grow file as pages are written.  */
#define	MAP_LOCAL	0x80	/* Copy the mapped region on fork.  */

/* Advice to `madvise'.  */
#define	MADV_NORMAL	0	/* No further special treatment.  */
#define	MADV_RANDOM	1	/* Expect random page references.  */
#define	MADV_SEQUENTIAL	2	/* Expect sequential page references.  */
#define	MADV_WILLNEED	3	/* Will need these pages.  */
#define	MADV_DONTNEED	4	/* Don't need these pages.  */

/* Flags to `msync'.  */
#define	MS_ASYNC	0x1		/* Return immediately, don't fsync.  */
#define	MS_INVALIDATE	0x2		/* Invalidate caches.  */


#include <sys/cdefs.h>

__BEGIN_DECLS
/* Map addresses starting near ADDR and extending for LEN bytes.  from
   OFFSET into the file FD describes according to PROT and FLAGS.  If ADDR
   is nonzero, it is the desired mapping address.  If the MAP_FIXED bit is
   set in FLAGS, the mapping will be at ADDR exactly (which must be
   page-aligned); otherwise the system chooses a convenient nearby address.
   The return value is the actual mapping address chosen or (caddr_t) -1
   for errors (in which case `errno' is set).  A successful `mmap' call
   deallocates any previous mapping for the affected region.  */

__caddr_t __mmap __P ((__caddr_t __addr, size_t __len,
		       int __prot, int __flags, int __fd, __off_t __offset));
__caddr_t mmap __P ((__caddr_t __addr, size_t __len,
		     int __prot, int __flags, int __fd, __off_t __offset));

/* Deallocate any mapping for the region starting at ADDR and extending LEN
   bytes.  Returns 0 if successful, -1 for errors (and sets errno).  */
int __munmap __P ((__caddr_t __addr, size_t __len));
int munmap __P ((__caddr_t __addr, size_t __len));

/* Change the memory protection of the region starting at ADDR and
   extending LEN bytes to PROT.  Returns 0 if successful, -1 for errors
   (and sets errno).  */
int __mprotect __P ((__caddr_t __addr, size_t __len, int __prot));
int mprotect __P ((__caddr_t __addr, size_t __len, int __prot));

/* Synchronize the region starting at ADDR and extending LEN bytes with the
   file it maps.  Filesystem operations on a file being mapped are
   unpredictable before this is done.  */
int msync __P ((caddr_t __addr, size_t __len, int __flags));

/* Advise the system about particular usage patterns the program follows
   for the region starting at ADDR and extending LEN bytes.  */
int madvise __P ((__caddr_t __addr, size_t __len, int __advice));

__END_DECLS


#endif	/* sys/mman.h */
