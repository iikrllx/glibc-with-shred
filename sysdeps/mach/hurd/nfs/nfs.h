/* <nfs/nfs.h> -- ill-specified NFS-related definitions
   Copyright (C) 1999 Free Software Foundation, Inc.
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

#ifndef _NFS_NFS_H
#define _NFS_NFS_H 1

/* This file is empty for now.  Its contents do not seem to be
   standardized in any way.  It exists solely for the sake of
   <rpcsvc/bootparam_prot.h> which insists on including <nfs/nfs.h>.

   For the time being, we just provide this file here to smooth building
   the libc distribution (i.e. librpcsvc).  We do not install this file for
   users, since we haven't really figured out what the right thing to go
   here is.  */

#endif /* nfs/nfs.h */
