/* Look up a symbol in a shared object loaded by `dlopen'.
   Copyright (C) 1999, 2000 Free Software Foundation, Inc.
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

#include <stddef.h>
#include <setjmp.h>
#include <libintl.h>

#include <dlfcn.h>
#include <ldsodefs.h>
#include <dl-hash.h>

void *
internal_function
_dl_sym (void *handle, const char *name, void *who)
{
  const ElfW(Sym) *ref = NULL;
  lookup_t result;

  if (handle == RTLD_DEFAULT)
    /* Search the global scope.  */
    result = _dl_lookup_symbol (name, NULL, &ref, _dl_global_scope, 0);
  else
    {
      struct link_map *l;
      struct link_map *match;
      ElfW(Addr) caller = (ElfW(Addr)) who;

      /* Find the highest-addressed object that CALLER is not below.  */
      match = NULL;
      for (l = _dl_loaded; l; l = l->l_next)
	if (caller >= l->l_addr && (!match || match->l_addr < l->l_addr))
	  match = l;

      if (handle != RTLD_NEXT)
	{
	  /* Search the scope of the given object.  */
	  struct link_map *map = handle;

	  if (match == NULL)
	    /* If the address is not recognized the call comes from the
	       main program (we hope).  */
	    match = _dl_loaded;

	  result = _dl_lookup_symbol (name, match, &ref, map->l_local_scope,
				      0);
	}
      else
	{
	  if (! match)
	    _dl_signal_error (0, NULL, N_("\
RTLD_NEXT used in code not dynamically loaded"));

	  l = match;
	  while (l->l_loader)
	    l = l->l_loader;

	  result = _dl_lookup_symbol_skip (name, l, &ref, l->l_local_scope,
					   match);
	}
    }

  if (ref)
    return DL_SYMBOL_ADDRESS (result, ref);

  return NULL;
}

void *
internal_function
_dl_vsym (void *handle, const char *name, const char *version, void *who)
{
  const ElfW(Sym) *ref = NULL;
  struct r_found_version vers;
  lookup_t result;

  /* Compute hash value to the version string.  */
  vers.name = version;
  vers.hidden = 1;
  vers.hash = _dl_elf_hash (version);
  /* We don't have a specific file where the symbol can be found.  */
  vers.filename = NULL;

  if (handle == RTLD_DEFAULT)
    /* Search the global scope.  */
    result = _dl_lookup_versioned_symbol (name, NULL, &ref, _dl_global_scope,
					  &vers, 0);
  else if (handle == RTLD_NEXT)
    {
      struct link_map *l;
      struct link_map *match;
      ElfW(Addr) caller = (ElfW(Addr)) who;

      /* Find the highest-addressed object that CALLER is not below.  */
      match = NULL;
      for (l = _dl_loaded; l; l = l->l_next)
	if (caller >= l->l_addr && (!match || match->l_addr < l->l_addr))
	  match = l;

      if (! match)
	_dl_signal_error (0, NULL, N_("\
RTLD_NEXT used in code not dynamically loaded"));

      l = match;
      while (l->l_loader)
	l = l->l_loader;

      result = _dl_lookup_versioned_symbol_skip (name, l, &ref,
						 l->l_local_scope,
						 &vers, match);
    }
  else
    {
      /* Search the scope of the given object.  */
      struct link_map *map = handle;
      result = _dl_lookup_versioned_symbol (name, map, &ref,
					    map->l_local_scope, &vers, 0);
    }

  if (ref)
    return DL_SYMBOL_ADDRESS (result, ref);

  return NULL;
}
