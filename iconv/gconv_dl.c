/* Handle loading/unloading of shared object for transformation.
   Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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
#include <gconv.h>
#include <inttypes.h>
#include <link.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include <bits/libc-lock.h>
#include <sys/param.h>


/* This is a tuning parameter.  If a transformation module is not used
   anymore it gets not immediately unloaded.  Instead we wait a certain
   number of load attempts for further modules.  If none of the
   subsequent load attempts name the same object it finally gets unloaded.
   Otherwise it is still available which hopefully is the frequent case.
   The following number is the number of unloading attempts we wait
   before unloading.  */
#define TRIES_BEFORE_UNLOAD	2


/* Structure describing one loaded shared object.  This normally are
   objects to perform conversation but as a special case the db shared
   object is also handled.  */
struct loaded_object
{
  /* Name of the object.  */
  const char *name;

  /* Reference counter for the db functionality.  If no conversion is
     needed we unload the db library.  */
  int counter;

  /* The handle for the shared object.  */
  void *handle;
};


/* Array of loaded objects.  This is shared by all threads so we have
   to use semaphores to access it.  */
static void *loaded;
__libc_lock_define_initialized (static, lock)



/* Comparison function for searching `loaded_object' tree.  */
static int
known_compare (const void *p1, const void *p2)
{
  const struct loaded_object *s1 = (const struct loaded_object *) p1;
  const struct loaded_object *s2 = (const struct loaded_object *) p2;

  return (intptr_t) s1->handle - (intptr_t) s2->handle;
}


static void
do_open (void *a)
{
  struct loaded_object *args = (struct loaded_object *) a;
  /* Open and relocate the shared object.  */
  args->handle = _dl_open (args->name, RTLD_LAZY);
}


static int
dlerror_run (void (*operate) (void *), void *args)
{
  char *last_errstring = NULL;
  const char *last_object_name = NULL;
  int result;

  (void) _dl_catch_error (&last_errstring, &last_object_name, operate, args);

  result = last_errstring != NULL;
  if (result)
    free (last_errstring);

  return result;
}


struct get_sym_args
{
  /* Arguments to get_sym.  */
  struct link_map *map;
  const char *name;

  /* Return values of get_sym.  */
  ElfW(Addr) loadbase;
  const ElfW(Sym) *ref;
};

static void
get_sym (void *a)
{
  struct get_sym_args *args = (struct get_sym_args *) a;
  struct link_map *scope[2] = { args->map, NULL };
  args->ref = NULL;
  args->loadbase = _dl_lookup_symbol (args->name, &args->ref,
				      scope, args->map->l_name, 0);
}


void *
__gconv_find_func (void *handle, const char *name)
{
  struct get_sym_args args;

  args.map = handle;
  args.name = name;

  return (dlerror_run (get_sym, &args) ? NULL
	  : (void *) (args.loadbase + args.ref->st_value));
}



/* Open the gconv database if necessary.  A non-negative return value
   means success.  */
void *
__gconv_find_shlib (const char *name)
{
  void *result = NULL;
  struct loaded_object *found;

  /* Acquire the lock.  */
  __libc_lock_lock (lock);

  /* Search the tree of shared objects previously requested.  Data in
     the tree are `loaded_object' structures, whose first member is a
     `const char *', the lookup key.  The search returns a pointer to
     the tree node structure; the first member of the is a pointer to
     our structure (i.e. what will be a `loaded_object'); since the
     first member of that is the lookup key string, &FCT_NAME is close
     enough to a pointer to our structure to use as a lookup key that
     will be passed to `known_compare' (above).  */

  found = __tfind (&name, loaded, known_compare);
  if (found == NULL)
    {
      /* This name was not known before.  */
      found = malloc (sizeof (struct loaded_object));
      if (found != NULL)
	{
	  /* Point the tree node at this new structure.  */
	  found->name = name;
	  found->counter = -TRIES_BEFORE_UNLOAD - 1;
	  found->handle = NULL;

	  if (__tsearch (found, &loaded, known_compare) == NULL)
	    {
	      /* Something went wrong while inserting the entry.  */
	      free (found);
	      found = NULL;
	    }
	}
    }

  /* Try to load the shared object if the usage count is 0.  This
     implies that if the shared object is not loadable, the handle is
     NULL and the usage count > 0.  */
  if (found != NULL)
    {
      if (found->counter < -TRIES_BEFORE_UNLOAD)
	{
	  if (dlerror_run (do_open, found) == 0)
	    found->counter = 1;
	}
      else if (found->handle != NULL)
	found->counter = MAX (found->counter + 1, 1);

      result = found->handle;
    }

  /* Release the lock.  */
  __libc_lock_unlock (lock);

  return result;
}


/* This is very ugly but the tsearch functions provide no way to pass
   information to the walker function.  So we use a global variable.
   It is MT safe since we use a lock.  */
static void *release_handle;

static void
do_release_shlib (const void *nodep, VISIT value, int level)
{
  struct loaded_object *obj = (struct loaded_object *) nodep;

  if (value != preorder && value != leaf)
    return;

  if (obj->handle == release_handle)
    /* This is the object we want to unload.  Now set the release
       counter to zero.  */
    obj->counter = 0;
  else if (obj->counter <= 0)
    {
      if (--obj->counter < -TRIES_BEFORE_UNLOAD && obj->handle != NULL)
	{
	  /* Unload the shared object.  We don't use the trick to
	     catch errors since in the case an error is signalled
	     something is really wrong.  */
	  _dl_close ((struct link_map *) obj->handle);

	  obj->handle = NULL;
	}
    }
}


/* Notify system that a shared object is not longer needed.  */
int
__gconv_release_shlib (void *handle)
{
  /* Acquire the lock.  */
  __libc_lock_lock (lock);

  /* Urgh, this is ugly but we have no other possibility.  */
  release_handle = handle;

  /* Process all entries.  Please note that we also visit entries
     with release counts <= 0.  This way we can finally unload them
     if necessary.  */
  __twalk (loaded, do_release_shlib);

  /* Release the lock.  */
  __libc_lock_unlock (lock);

  return GCONV_OK;
}
