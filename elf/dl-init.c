/* Return the next shared object initializer function not yet run.
   Copyright (C) 1995, 1996, 1998, 1999, 2000 Free Software Foundation, Inc.
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
#include <ldsodefs.h>


/* Type of the initializer.  */
typedef void (*init_t) (int, char **, char **);


static void
internal_function
_dl_init_rec (struct link_map *map, int argc, char **argv, char **env)
{
  unsigned int i;

  /* Stupid users forces the ELF specification to be changed.  It now
     says that the dynamic loader is responsible for determining the
     order in which the constructors have to run.  The constructors
     for all dependencies of an object must run before the constructor
     for the object itself.  Circular dependencies are left unspecified.

     This is highly questionable since it puts the burden on the dynamic
     loader which has to find the dependencies at runtime instead of
     letting the user do it right.  Stupidity rules!  */

  i = map->l_searchlist.r_nlist;
  while (i-- > 0)
    {
      struct link_map *l = map->l_initfini[i];
      int message_written;
      init_t init;

      if (l->l_init_called)
	/* This object is all done.  */
	continue;

      /* Avoid handling this constructor again in case we have a circular
	 dependency.  */
      l->l_init_called = 1;

      /* Check for object which constructors we do not run here.  */
      if (l->l_name[0] == '\0' && l->l_type == lt_executable)
	continue;

      /* See whether any dependent objects are not yet initialized.
	 XXX Is this necessary?  I'm not sure anymore...  */
      if (l->l_searchlist.r_nlist > 1)
	_dl_init_rec (l, argc, argv, env);

      /* Now run the local constructors.  There are several of them:
	 - the one named by DT_INIT
	 - the others in the DT_INIT_ARRAY.
      */
      message_written = 0;
      if (l->l_info[DT_INIT])
	{
	  /* Print a debug message if wanted.  */
	  if (_dl_debug_impcalls)
	    {
	      _dl_debug_message (1, "\ncalling init: ",
				 l->l_name[0] ? l->l_name : _dl_argv[0],
				 "\n\n", NULL);
	      message_written = 1;
	    }

	  init = (init_t) (l->l_addr + l->l_info[DT_INIT]->d_un.d_ptr);

	  /* Call the function.  */
	  init (argc, argv, env);
	}

      /* Next see whether there is an array with initialiazation functions.  */
      if (l->l_info[DT_INIT_ARRAY])
	{
	  unsigned int j;
	  unsigned int jm;
	  ElfW(Addr) *addrs;

	  jm = l->l_info[DT_INIT_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr));

	  if (jm > 0 && _dl_debug_impcalls && ! message_written)
	    _dl_debug_message (1, "\ncalling init: ",
			       l->l_name[0] ? l->l_name : _dl_argv[0],
			       "\n\n", NULL);

	  addrs = (ElfW(Addr) *) (l->l_info[DT_INIT_ARRAY]->d_un.d_ptr
				  + l->l_addr);
	  for (j = 0; j < jm; ++j)
	    ((init_t) addrs[j]) (argc, argv, env);
	}
    }
}


void
internal_function
_dl_init (struct link_map *main_map, int argc, char **argv, char **env)
{
  struct r_debug *r;

  /* Notify the debugger we have added some objects.  We need to call
     _dl_debug_initialize in a static program in case dynamic linking has
     not been used before.  */
  r = _dl_debug_initialize (0);
  r->r_state = RT_ADD;
  _dl_debug_state ();

  /* Recursively call the constructors.  */
  _dl_init_rec (main_map, argc, argv, env);

  /* Notify the debugger all new objects are now ready to go.  */
  r->r_state = RT_CONSISTENT;
  _dl_debug_state ();
}
