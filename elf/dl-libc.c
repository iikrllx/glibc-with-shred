/* Handle loading and unloading shared objects for internal libc purposes.
   Copyright (C) 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Zack Weinberg <zack@rabi.columbia.edu>, 1999.

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

#include <dlfcn.h>
#include <stdlib.h>
#include <ldsodefs.h>

/* The purpose of this file is to provide wrappers around the dynamic
   linker error mechanism (similar to dlopen() et al in libdl) which
   are usable from within libc.  Generally we want to throw away the
   string that dlerror() would return and just pass back a null pointer
   for errors.  This also lets the rest of libc not know about the error
   handling mechanism.

   Much of this code came from gconv_dl.c with slight modifications. */

static int
internal_function
dlerror_run (void (*operate) (void *), void *args)
{
  char *last_errstring = NULL;
  int result;

  (void) _dl_catch_error (&last_errstring, operate, args);

  result = last_errstring != NULL;
  if (result)
    free (last_errstring);

  return result;
}

/* These functions are called by dlerror_run... */

struct do_dlopen_args
{
  /* Argument to do_dlopen.  */
  const char *name;

  /* Return from do_dlopen.  */
  struct link_map *map;
};

struct do_dlsym_args
{
  /* Arguments to do_dlsym.  */
  struct link_map *map;
  const char *name;

  /* Return values of do_dlsym.  */
  ElfW(Addr) loadbase;
  const ElfW(Sym) *ref;
};

static void
do_dlopen (void *ptr)
{
  struct do_dlopen_args *args = (struct do_dlopen_args *) ptr;
  /* Open and relocate the shared object.  */
  args->map = _dl_open (args->name, RTLD_LAZY, NULL);
}

static void
do_dlsym (void *ptr)
{
  struct do_dlsym_args *args = (struct do_dlsym_args *) ptr;
  args->ref = NULL;
  args->loadbase = _dl_lookup_symbol (args->name, &args->ref,
				      args->map->l_local_scope,
				      args->map->l_name, 0);
}

static void
do_dlclose (void *ptr)
{
    _dl_close ((struct link_map *) ptr);
}

/* ... and these functions call dlerror_run. */

void *
__libc_dlopen (const char *__name)
{
  struct do_dlopen_args args;
  args.name = __name;

  return (dlerror_run (do_dlopen, &args) ? NULL : (void *) args.map);
}

void *
__libc_dlsym (void *__map, const char *__name)
{
  struct do_dlsym_args args;
  args.map = __map;
  args.name = __name;

  return (dlerror_run (do_dlsym, &args) ? NULL
	  : (void *) (args.loadbase + args.ref->st_value));
}

int
__libc_dlclose (void *__map)
{
  return dlerror_run (do_dlclose, __map);
}
