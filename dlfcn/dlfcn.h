/* User functions for run-time dynamic loading.
   Copyright (C) 1995-1999,2000,2001,2003 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef	_DLFCN_H
#define	_DLFCN_H 1

#include <features.h>
#define __need_size_t
#include <stddef.h>

/* Collect various system dependent definitions and declarations.  */
#include <bits/dlfcn.h>


#ifdef __USE_GNU
/* If the first argument of `dlsym' or `dlvsym' is set to RTLD_NEXT
   the run-time address of the symbol called NAME in the next shared
   object is returned.  The "next" relation is defined by the order
   the shared objects were loaded.  */
# define RTLD_NEXT	((void *) -1l)

/* If the first argument to `dlsym' or `dlvsym' is set to RTLD_DEFAULT
   the run-time address of the symbol called NAME in the global scope
   is returned.  */
# define RTLD_DEFAULT	((void *) 0)
#endif


__BEGIN_DECLS

/* Open the shared object FILE and map it in; return a handle that can be
   passed to `dlsym' to get symbol values from it.  */
extern void *dlopen (__const char *__file, int __mode) __THROW;

/* Unmap and close a shared object opened by `dlopen'.
   The handle cannot be used again after calling `dlclose'.  */
extern int dlclose (void *__handle) __THROW;

/* Find the run-time address in the shared object HANDLE refers to
   of the symbol called NAME.  */
extern void *dlsym (void *__restrict __handle,
		    __const char *__restrict __name) __THROW;

#ifdef __USE_GNU
/* Find the run-time address in the shared object HANDLE refers to
   of the symbol called NAME with VERSION.  */
extern void *dlvsym (void *__restrict __handle,
		     __const char *__restrict __name,
		     __const char *__restrict __version) __THROW;
#endif

/* When any of the above functions fails, call this function
   to return a string describing the error.  Each call resets
   the error string so that a following call returns null.  */
extern char *dlerror (void) __THROW;


#ifdef __USE_GNU
/* Structure containing information about object searched using
   `dladdr'.  */
typedef struct
{
  __const char *dli_fname;	/* File name of defining object.  */
  void *dli_fbase;		/* Load address of that object.  */
  __const char *dli_sname;	/* Name of nearest symbol.  */
  void *dli_saddr;		/* Exact value of nearest symbol.  */
} Dl_info;

/* Fill in *INFO with the following information about ADDRESS.
   Returns 0 iff no shared object's segments contain that address.  */
extern int dladdr (__const void *__address, Dl_info *__info) __THROW;

/* Same as `dladdr', but additionally sets *EXTRA_INFO according to FLAGS.  */
extern int dladdr1 (__const void *__address, Dl_info *__info,
		    void **__extra_info, int __flags) __THROW;

/* These are the possible values for the FLAGS argument to `dladdr1'.
   This indicates what extra information is stored at *EXTRA_INFO.
   It may also be zero, in which case the EXTRA_INFO argument is not used.  */
enum
  {
    /* Matching symbol table entry (const ElfNN_Sym *).  */
    RTLD_DL_SYMENT = 1,

    /* The object containing the address (struct link_map *).  */
    RTLD_DL_LINKMAP = 2
  };


/* Get information about the shared object HANDLE refers to.
   REQUEST is from among the values below, and determines the use of ARG.

   On success, returns zero.  On failure, returns -1 and records an error
   message to be fetched with `dlerror'.  */
extern int dlinfo (void *__restrict __handle,
		   int __request, void *__restrict __arg);

/* These are the possible values for the REQUEST argument to `dlinfo'.  */
enum
  {
    /* Treat ARG as `struct link_map **';
       store the `struct link_map *' for HANDLE there.  */
    RTLD_DI_LINKMAP = 2,

    /* Treat ARG as `Dl_serinfo *' (see below), and fill in to describe the
       directories that will be searched for dependencies of this object.
       RTLD_DI_SERINFOSIZE fills in just the `dls_cnt' and `dls_size'
       entries to indicate the size of the buffer that must be passed to
       RTLD_DI_SERINFO to fill in the full information.  */
    RTLD_DI_SERINFO = 4,
    RTLD_DI_SERINFOSIZE = 5,

    /* Treat ARG as `char *', and store there the directory name used to
       expand $ORIGIN in this shared object's dependency file names.  */
    RTLD_DI_ORIGIN = 6,

    RTLD_DI_LMID = 1,		/* Unsupported, defined by Solaris.  */
    RTLD_DI_CONFIGADDR = 3	/* Unsupported, defined by Solaris.  */
  };


/* This is the type of elements in `Dl_serinfo', below.
   The `dls_name' member points to space in the buffer passed to `dlinfo'.  */
typedef struct
{
  char *dls_name;		/* Name of library search path directory.  */
  unsigned int dls_flags;	/* Indicates where this directory came from. */
} Dl_serpath;

/* This is the structure that must be passed (by reference) to `dlinfo' for
   the RTLD_DI_SERINFO and RTLD_DI_SERINFOSIZE requests.  */
typedef struct
{
  size_t dls_size;		/* Size in bytes of the whole buffer.  */
  unsigned int dls_cnt;		/* Number of elements in `dls_serpath'.  */
  Dl_serpath dls_serpath[1];	/* Actually longer, dls_cnt elements.  */
} Dl_serinfo;
#endif /* __USE_GNU */


__END_DECLS

#endif	/* dlfcn.h */
