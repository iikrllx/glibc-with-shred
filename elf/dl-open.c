/* Load a shared object at runtime, relocate it, and run its initializer.
   Copyright (C) 1996, 1997, 1998 Free Software Foundation, Inc.
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

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>		/* Check whether MAP_COPY is defined.  */
#include <bits/libc-lock.h>
#include <elf/ldsodefs.h>


extern ElfW(Addr) _dl_sysdep_start (void **start_argptr,
				    void (*dl_main) (const ElfW(Phdr) *phdr,
						     ElfW(Word) phnum,
						     ElfW(Addr) *user_entry));
weak_extern (_dl_sysdep_start)

/* This function is used to unload the cache file if necessary.  */
extern void _dl_unload_cache (void);

extern int __libc_multiple_libcs;	/* Defined in init-first.c.  */

extern int __libc_argc;
extern char **__libc_argv;

extern char **__environ;

static size_t _dl_global_scope_alloc;


/* During the program run we must not modify the global data of
   loaded shared object simultanously in two threads.  Therefore we
   protect `_dl_open' and `_dl_close' in dl-close.c.

   This must be a recursive lock since the initializer function of
   the loaded object might as well require a call to this function.
   At this time it is not anymore a problem to modify the tables.  */
__libc_lock_define_initialized_recursive (, _dl_load_lock)


/* We must be carefull not to leave us in an inconsistent state.  Thus we
   catch any error and re-raise it after cleaning up.  */

struct dl_open_args
{
  const char *file;
  int mode;
  struct link_map *map;
};

static void
dl_open_worker (void *a)
{
  struct dl_open_args *args = a;
  const char *file = args->file;
  int mode = args->mode;
  struct link_map *new, *l;
  ElfW(Addr) init;
  struct r_debug *r;

  /* Load the named object.  */
  args->map = new = _dl_map_object (NULL, file, 0, lt_loaded, 0);
  if (new->l_searchlist.r_list)
    /* It was already open.  */
    return;

  /* Load that object's dependencies.  */
  _dl_map_object_deps (new, NULL, 0, 0);

  /* So far, so good.  Now check the versions.  */
  (void) _dl_check_all_versions (new, 0);

  /* Relocate the objects loaded.  We do this in reverse order so that copy
     relocs of earlier objects overwrite the data written by later objects.  */

  l = new;
  while (l->l_next)
    l = l->l_next;
  while (1)
    {
      if (! l->l_relocated)
	{
#ifdef PIC
	  if (_dl_profile != NULL)
	    {
	      /* If this here is the shared object which we want to profile
		 make sure the profile is started.  We can find out whether
	         this is necessary or not by observing the `_dl_profile_map'
	         variable.  If was NULL but is not NULL afterwars we must
		 start the profiling.  */
	      struct link_map *old_profile_map = _dl_profile_map;

	      _dl_relocate_object (l, l->l_scope, 1, 1);

	      if (old_profile_map == NULL && _dl_profile_map != NULL)
		/* We must prepare the profiling.  */
		_dl_start_profile (_dl_profile_map, _dl_profile_output);
	    }
	  else
#endif
	    _dl_relocate_object (l, l->l_scope,
				 (mode & RTLD_BINDING_MASK) == RTLD_LAZY, 0);
	}

      if (l == new)
	break;
      l = l->l_prev;
    }

  new->l_global = (mode & RTLD_GLOBAL) ? 1 : 0;
  if (new->l_global)
    {
      /* The symbols of the new object and its dependencies are to be
	 introduced into the global scope that will be used to resolve
	 references from other dynamically-loaded objects.

	 The global scope is the searchlist in the main link map.  We
	 extend this list if necessary.  There is one problem though:
	 since this structure was allocated very early (before the libc
	 is loaded) the memory it uses is allocated by the malloc()-stub
	 in the ld.so.  When we come here these functions are not used
	 anymore.  Instead the malloc() implementation of the libc is
	 used.  But this means the block from the main map cannot be used
	 in an realloc() call.  Therefore we allocate a completely new
	 array the first time we have to add something to the locale scope.  */
      if (_dl_global_scope_alloc == 0)
	{
	  /* This is the first dynamic object given global scope.  */
	  struct link_map **new_global;

	  _dl_global_scope_alloc = _dl_main_searchlist->r_nlist + 8;
	  new_global = (struct link_map **)
	    malloc (_dl_global_scope_alloc * sizeof (struct link_map *));
	  if (new_global == NULL)
	    {
	      _dl_global_scope_alloc = 0;
	    nomem:
	      new->l_global = 0;
	      _dl_signal_error (ENOMEM, file, "cannot extend global scope");
	    }

	  /* Copy over the old entries.  */
	  memcpy (new_global, _dl_main_searchlist->r_list,
		  (_dl_main_searchlist->r_nlist * sizeof (struct link_map *)));

	  _dl_main_searchlist->r_list = new_global;
	}
      else if (_dl_main_searchlist->r_nlist == _dl_global_scope_alloc)
	{
	  /* We have to extend the existing array of link maps in the
	     main map.  */
	  struct link_map **new_global;

	  new_global = (struct link_map **)
	    malloc ((_dl_global_scope_alloc + 8) * sizeof (struct link_map *));
	  if (new_global == NULL)
	    goto nomem;

	  _dl_global_scope_alloc += 8;
	  _dl_main_searchlist->r_list = new_global;
	}

      /* Now add the new entry.  */
      _dl_main_searchlist->r_list[_dl_main_searchlist->r_nlist] = new;

      /* XXX Do we have to add something to r_dupsearchlist???  --drepper */
    }


  /* Notify the debugger we have added some objects.  We need to call
     _dl_debug_initialize in a static program in case dynamic linking has
     not been used before.  */
  r = _dl_debug_initialize (0);
  r->r_state = RT_ADD;
  _dl_debug_state ();

  /* Run the initializer functions of new objects.  */
  while ((init = _dl_init_next (&new->l_searchlist)))
    (*(void (*) (int, char **, char **)) init) (__libc_argc, __libc_argv,
						__environ);

  if (new->l_global)
    /* Now we can make the new map available in the global scope.  */
    ++_dl_main_searchlist->r_nlist;

  if (_dl_sysdep_start == NULL)
    /* We must be the static _dl_open in libc.a.  A static program that
       has loaded a dynamic object now has competition.  */
    __libc_multiple_libcs = 1;
}


struct link_map *
internal_function
_dl_open (const char *file, int mode)
{
  struct dl_open_args args;
  char *errstring;
  int errcode;

  /* Make sure we are alone.  */
  __libc_lock_lock (_dl_load_lock);

  args.file = file;
  args.mode = mode;
  args.map = NULL;
  errcode = _dl_catch_error (&errstring, dl_open_worker, &args);

#ifndef MAP_COPY
  /* We must munmap() the cache file.  */
  _dl_unload_cache ();
#endif

  /* Release the lock.  */
  __libc_lock_unlock (_dl_load_lock);

  if (errstring)
    {
      /* Some error occured during loading.  */
      char *local_errstring;

      /* Remove the object from memory.  It may be in an inconsistent
	 state if relocation failed, for example.  */
      if (args.map)
	_dl_close (args.map);

      /* Make a local copy of the error string so that we can release the
	 memory allocated for it.  */
      local_errstring = strdupa (errstring);
      free (errstring);

      /* Reraise the error.  */
      _dl_signal_error (errcode, NULL, local_errstring);
    }

  return args.map;
}
