/* Close a shared object opened by `_dl_open'.
   Copyright (C) 1996, 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
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

#include <assert.h>
#include <dlfcn.h>
#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <bits/libc-lock.h>
#include <ldsodefs.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <stdio-common/_itoa.h>


/* Type of the constructor functions.  */
typedef void (*fini_t) (void);


/* During the program run we must not modify the global data of
   loaded shared object simultanously in two threads.  Therefore we
   protect `dlopen' and `dlclose' in dlclose.c.  */
__libc_lock_define (extern, _dl_load_lock)

void
internal_function
_dl_close (void *_map)
{
  struct link_map **list;
  struct link_map **rellist;
  struct link_map *map = _map;
  unsigned int nsearchlist;
  unsigned int nrellist;
  unsigned int i;

  /* First see whether we can remove the object at all.  */
  if (map->l_flags_1 & DF_1_NODELETE)
    /* Nope.  Do nothing.  */
    return;

  if (map->l_opencount == 0)
    _dl_signal_error (0, map->l_name, N_("shared object not open"));

  /* Acquire the lock.  */
  __libc_lock_lock (_dl_load_lock);

  /* Decrement the reference count.  */
  if (map->l_opencount > 1 || map->l_type != lt_loaded)
    {
      /* There are still references to this object.  Do nothing more.  */
      if (__builtin_expect (_dl_debug_files, 0))
	{
	  char buf[20];

	  buf[sizeof buf - 1] = '\0';

	  _dl_debug_message (1, "\nclosing file=", map->l_name,
			     "; opencount == ",
			     _itoa_word (map->l_opencount,
					 buf + sizeof buf - 1, 10, 0),
			     "\n", NULL);
	}

      --map->l_opencount;
      __libc_lock_unlock (_dl_load_lock);
      return;
    }

  list = map->l_searchlist.r_list;
  nsearchlist = map->l_searchlist.r_nlist;

  rellist = map->l_reldeps;
  nrellist = map->l_reldepsact;

  /* Call all termination functions at once.  */
  for (i = 0; i < nsearchlist; ++i)
    {
      struct link_map *imap = map->l_initfini[i];
      if (imap->l_opencount == 1 && imap->l_type == lt_loaded
	  && (imap->l_info[DT_FINI] || imap->l_info[DT_FINI_ARRAY])
	  && ! (list[i]->l_flags_1 & DF_1_NODELETE)
	  /* Skip any half-cooked objects that were never initialized.  */
	  && imap->l_init_called)
	{
	  /* When debugging print a message first.  */
	  if (__builtin_expect (_dl_debug_impcalls, 0))
	    _dl_debug_message (1, "\ncalling fini: ", imap->l_name,
			       "\n\n", NULL);

	  /* Call its termination function.  */
	  if (imap->l_info[DT_FINI_ARRAY] != NULL)
	    {
	      ElfW(Addr) *array =
		(ElfW(Addr) *) (imap->l_addr
				+ imap->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
	      unsigned int sz = (imap->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
				 / sizeof (ElfW(Addr)));
	      unsigned int cnt;

	      for (cnt = 0; cnt < sz; ++cnt)
		((fini_t) (imap->l_addr + array[cnt])) ();
	    }

	  /* Next try the old-style destructor.  */
	  if (imap->l_info[DT_FINI] != NULL)
	    (*(void (*) (void)) ((void *) imap->l_addr
				 + imap->l_info[DT_FINI]->d_un.d_ptr)) ();
	}
    }

  /* Notify the debugger we are about to remove some loaded objects.  */
  _r_debug.r_state = RT_DELETE;
  _dl_debug_state ();

  /* The search list contains a counted reference to each object it
     points to, the 0th elt being MAP itself.  Decrement the reference
     counts on all the objects MAP depends on.  */
  for (i = 0; i < nsearchlist; ++i)
    if (! (list[i]->l_flags_1 & DF_1_NODELETE))
      --list[i]->l_opencount;

  /* Check each element of the search list to see if all references to
     it are gone.  */
  for (i = 0; i < nsearchlist; ++i)
    {
      struct link_map *imap = list[i];
      if (imap->l_opencount == 0 && imap->l_type == lt_loaded)
	{
	  struct libname_list *lnp;

	  /* That was the last reference, and this was a dlopen-loaded
	     object.  We can unmap it.  */
	  if (imap->l_global)
	    {
	      /* This object is in the global scope list.  Remove it.  */
	      int cnt = _dl_main_searchlist->r_nlist;

	      do
		--cnt;
	      while (_dl_main_searchlist->r_list[cnt] != imap);

	      /* The object was already correctly registered.  */
	      while (++cnt < _dl_main_searchlist->r_nlist)
		_dl_main_searchlist->r_list[cnt - 1]
		  = _dl_main_searchlist->r_list[cnt];

	      --_dl_main_searchlist->r_nlist;
	    }

	  /* We can unmap all the maps at once.  We determined the
	     start address and length when we loaded the object and
	     the `munmap' call does the rest.  */
	  __munmap ((void *) imap->l_map_start,
		    imap->l_map_end - imap->l_map_start);

	  /* Finally, unlink the data structure and free it.  */
#ifdef SHARED
	  /* We will unlink the first object only if this is a statically
	     linked program.  */
	  assert (imap->l_prev != NULL);
	  imap->l_prev->l_next = imap->l_next;
#else
	  if (imap->l_prev != NULL)
	    imap->l_prev->l_next = imap->l_next;
	  else
	    _dl_loaded = imap->l_next;
#endif
	  --_dl_nloaded;
	  if (imap->l_next)
	    imap->l_next->l_prev = imap->l_prev;

	  if (imap->l_versions != NULL)
	    free (imap->l_versions);
	  if (imap->l_origin != NULL && imap->l_origin != (char *) -1)
	    free ((char *) imap->l_origin);

	  /* This name always is allocated.  */
	  free (imap->l_name);
	  /* Remove the list with all the names of the shared object.  */
	  lnp = imap->l_libname;
	  do
	    {
	      struct libname_list *this = lnp;
	      lnp = lnp->next;
	      free (this);
	    }
	  while (lnp != NULL);

	  /* Remove the searchlists.  */
	  if (imap != map)
	    {
	      if (imap->l_searchlist.r_list != NULL)
		free (imap->l_searchlist.r_list);
	      else if (imap->l_initfini != NULL)
		free (imap->l_initfini);
	    }

	  if (imap->l_phdr_allocated)
	    free ((void *) imap->l_phdr);

	  if (imap->l_rpath_dirs.dirs != (void *) -1)
	    free (imap->l_rpath_dirs.dirs);
	  if (imap->l_runpath_dirs.dirs != (void *) -1)
	    free (imap->l_runpath_dirs.dirs);

	  free (imap);
	}
    }

  /* Now we can perhaps also remove the modules for which we had
     dependencies because of symbol lookup.  */
  if (rellist != NULL)
    {
      while (nrellist-- > 0)
	_dl_close (rellist[nrellist]);

      free (rellist);
    }

  free (list);

  if (_dl_global_scope_alloc != 0
      && _dl_main_searchlist->r_nlist == _dl_initial_searchlist.r_nlist)
    {
      /* All object dynamically loaded by the program are unloaded.  Free
	 the memory allocated for the global scope variable.  */
      struct link_map **old = _dl_main_searchlist->r_list;

      /* Put the old map in.  */
      _dl_main_searchlist->r_list = _dl_initial_searchlist.r_list;
      /* Signal that the original map is used.  */
      _dl_global_scope_alloc = 0;

      /* Now free the old map.  */
      free (old);
    }

  /* Notify the debugger those objects are finalized and gone.  */
  _r_debug.r_state = RT_CONSISTENT;
  _dl_debug_state ();

  /* Release the lock.  */
  __libc_lock_unlock (_dl_load_lock);
}
