/* Copyright (C) 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <bits/libc-lock.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldsodefs.h>		/* We need some help from ld.so.  */

#if !defined DO_STATIC_NSS || defined PIC
# include <gnu/lib-names.h>
#endif

#include "nsswitch.h"

/* Prototypes for the local functions.  */
static name_database *nss_parse_file (const char *fname) internal_function;
static name_database_entry *nss_getline (char *line) internal_function;
static service_user *nss_parse_service_list (const char *line)
     internal_function;
static service_library *nss_new_service (name_database *database,
					 const char *name) internal_function;


/* Declare external database variables.  */
#define DEFINE_DATABASE(name)						      \
  extern service_user *__nss_##name##_database;				      \
  weak_extern (__nss_##name##_database)
#include "databases.def"
#undef DEFINE_DATABASE

/* Structure to map database name to variable.  */
static struct
{
  const char *name;
  service_user **dbp;
} databases[] =
{
#define DEFINE_DATABASE(name)						      \
  { #name, &__nss_##name##_database },
#include "databases.def"
#undef DEFINE_DATABASE
};


__libc_lock_define_initialized (static, lock)

#if !defined DO_STATIC_NSS || defined PIC
/* String with revision number of the shared object files.  */
static const char *const __nss_shlib_revision = LIBNSS_FILES_SO + 15;
#endif

/* The root of the whole data base.  */
static name_database *service_table;


/* -1 == database not found
    0 == database entry pointer stored */
int
__nss_database_lookup (const char *database, const char *alternate_name,
		       const char *defconfig, service_user **ni)
{
  /* Prevent multiple threads to change the service table.  */
  __libc_lock_lock (lock);

  /* Reconsider database variable in case some other thread called
     `__nss_configure_lookup' while we waited for the lock.  */
  if (*ni != NULL)
    {
      __libc_lock_unlock (lock);
      return 0;
    }

  /* Are we initialized yet?  */
  if (service_table == NULL)
    /* Read config file.  */
    service_table = nss_parse_file (_PATH_NSSWITCH_CONF);

  /* Test whether configuration data is available.  */
  if (service_table != NULL)
    {
      /* Return first `service_user' entry for DATABASE.  */
      name_database_entry *entry;

      /* XXX Could use some faster mechanism here.  But each database is
	 only requested once and so this might not be critical.  */
      for (entry = service_table->entry; entry != NULL; entry = entry->next)
	if (strcmp (database, entry->name) == 0)
	  *ni = entry->service;

      if (*ni == NULL && alternate_name != NULL)
	/* We haven't found an entry so far.  Try to find it with the
	   alternative name.  */
	for (entry = service_table->entry; entry != NULL; entry = entry->next)
	  if (strcmp (alternate_name, entry->name) == 0)
	    *ni = entry->service;
    }

  /* No configuration data is available, either because nsswitch.conf
     doesn't exist or because it doesn't has a line for this database.

     DEFCONFIG specifies the default service list for this database,
     or null to use the most common default.  */
  if (*ni == NULL)
    *ni = nss_parse_service_list (defconfig
				  ?: "nis [NOTFOUND=return] files");

  __libc_lock_unlock (lock);

  return 0;
}


/* -1 == not found
    0 == function found
    1 == finished */
int
__nss_lookup (service_user **ni, const char *fct_name, void **fctp)
{
  *fctp = __nss_lookup_function (*ni, fct_name);

  while (*fctp == NULL
	 && nss_next_action (*ni, NSS_STATUS_UNAVAIL) == NSS_ACTION_CONTINUE
	 && (*ni)->next != NULL)
    {
      *ni = (*ni)->next;

      *fctp = __nss_lookup_function (*ni, fct_name);
    }

  return *fctp != NULL ? 0 : (*ni)->next == NULL ? 1 : -1;
}


/* -1 == not found
    0 == adjusted for next function
    1 == finished */
int
__nss_next (service_user **ni, const char *fct_name, void **fctp, int status,
	    int all_values)
{
  if (all_values)
    {
      if (nss_next_action (*ni, NSS_STATUS_TRYAGAIN) == NSS_ACTION_RETURN
	  && nss_next_action (*ni, NSS_STATUS_UNAVAIL) == NSS_ACTION_RETURN
	  && nss_next_action (*ni, NSS_STATUS_NOTFOUND) == NSS_ACTION_RETURN
	  && nss_next_action (*ni, NSS_STATUS_SUCCESS) == NSS_ACTION_RETURN)
	return 1;
    }
  else
    {
      /* This is really only for debugging.  */
       if (NSS_STATUS_TRYAGAIN > status || status > NSS_STATUS_RETURN)
	 __libc_fatal ("illegal status in " __FUNCTION__);

       if (nss_next_action (*ni, status) == NSS_ACTION_RETURN)
	 return 1;
    }

  if ((*ni)->next == NULL)
    return -1;

  do
    {
      *ni = (*ni)->next;

      *fctp = __nss_lookup_function (*ni, fct_name);
    }
  while (*fctp == NULL
	 && nss_next_action (*ni, NSS_STATUS_UNAVAIL) == NSS_ACTION_CONTINUE
	 && (*ni)->next != NULL);

  return *fctp != NULL ? 0 : -1;
}


int
__nss_configure_lookup (const char *dbname, const char *service_line)
{
  service_user *new_db;
  size_t cnt;

  for (cnt = 0; cnt < sizeof databases; ++cnt)
    {
      int cmp = strcmp (dbname, databases[cnt].name);
      if (cmp == 0)
	break;
      if (cmp < 0)
	{
	  __set_errno (EINVAL);
	  return -1;
	}
    }

  if (cnt == sizeof databases)
    {
      __set_errno (EINVAL);
      return -1;
    }

  /* Test whether it is really used.  */
  if (databases[cnt].dbp == NULL)
    /* Nothing to do, but we could do.  */
    return 0;

  /* Try to generate new data.  */
  new_db = nss_parse_service_list (service_line);
  if (new_db == NULL)
    {
      /* Illegal service specification.  */
      __set_errno (EINVAL);
      return -1;
    }

  /* Prevent multiple threads to change the service table.  */
  __libc_lock_lock (lock);

  /* Install new rules.  */
  *databases[cnt].dbp = new_db;

  __libc_lock_unlock (lock);

  return 0;
}


#if !defined DO_STATIC_NSS || defined PIC
static int
nss_dlerror_run (void (*operate) (void *), void *args)
{
  char *last_errstring = NULL;
  int result;

  (void) _dl_catch_error (&last_errstring, operate, args);

  result = last_errstring != NULL;
  if (result)
    free (last_errstring);

  return result;
}


struct do_open_args
{
  /* Argument to do_open.  */
  char *shlib_name;
  service_user *ni;
};

struct get_sym_args
{
  /* Arguments to get_sym.  */
  struct link_map *map;
  char *name;

  /* Return values of get_sym.  */
  ElfW(Addr) loadbase;
  const ElfW(Sym) *ref;
};

static void
do_open (void *a)
{
  struct do_open_args *args = (struct do_open_args *) a;
  /* Open and relocate the shared object.  */
  args->ni->library->lib_handle = _dl_open (args->shlib_name, RTLD_LAZY, NULL);
}

static void
get_sym (void *a)
{
  struct get_sym_args *args = (struct get_sym_args *) a;
  args->ref = NULL;
  args->loadbase = _dl_lookup_symbol (args->name, &args->ref,
				      args->map->l_local_scope,
				      args->map->l_name, 0);
}
#endif

/* Comparison function for searching NI->known tree.  */
static int
known_compare (const void *p1, const void *p2)
{
  return p1 == p2 ? 0 : strcmp (*(const char *const *) p1,
				*(const char *const *) p2);
}


void *
__nss_lookup_function (service_user *ni, const char *fct_name)
{
  void **found, *result;

  /* We now modify global data.  Protect it.  */
  __libc_lock_lock (lock);

  /* Search the tree of functions previously requested.  Data in the
     tree are `known_function' structures, whose first member is a
     `const char *', the lookup key.  The search returns a pointer to
     the tree node structure; the first member of the is a pointer to
     our structure (i.e. what will be a `known_function'); since the
     first member of that is the lookup key string, &FCT_NAME is close
     enough to a pointer to our structure to use as a lookup key that
     will be passed to `known_compare' (above).  */

  found = __tsearch (&fct_name, (void **) &ni->known, &known_compare);
  if (*found != &fct_name)
    /* The search found an existing structure in the tree.  */
    result = ((known_function *) *found)->fct_ptr;
  else
    {
      /* This name was not known before.  Now we have a node in the tree
	 (in the proper sorted position for FCT_NAME) that points to
	 &FCT_NAME instead of any real `known_function' structure.
	 Allocate a new structure and fill it in.  */

      known_function *known = malloc (sizeof *known);
      if (! known)
	{
	remove_from_tree:
	  /* Oops.  We can't instantiate this node properly.
	     Remove it from the tree.  */
	  __tdelete (&fct_name, (void **) &ni->known, &known_compare);
	  result = NULL;
	}
      else
	{
	  /* Point the tree node at this new structure.  */
	  *found = known;
	  known->fct_name = fct_name;

	  if (ni->library == NULL)
	    {
	      /* This service has not yet been used.  Fetch the service
		 library for it, creating a new one if need be.  If there
		 is no service table from the file, this static variable
		 holds the head of the service_library list made from the
		 default configuration.  */
	      static name_database default_table;
	      ni->library = nss_new_service (service_table ?: &default_table,
					     ni->name);
	      if (ni->library == NULL)
		{
		  /* This only happens when out of memory.  */
		  free (known);
		  goto remove_from_tree;
		}
	    }

#if !defined DO_STATIC_NSS || defined PIC
	  if (ni->library->lib_handle == NULL)
	    {
	      /* Load the shared library.  */
	      size_t shlen = (7 + strlen (ni->library->name) + 3
			      + strlen (__nss_shlib_revision) + 1);
	      int saved_errno = errno;
	      struct do_open_args args;
	      args.shlib_name = __alloca (shlen);
	      args.ni = ni;

	      /* Construct shared object name.  */
	      __stpcpy (__stpcpy (__stpcpy (__stpcpy (args.shlib_name,
						      "libnss_"),
					    ni->library->name),
				  ".so"),
			__nss_shlib_revision);

	      if (nss_dlerror_run (do_open, &args) != 0)
		{
		  /* Failed to load the library.  */
		  ni->library->lib_handle = (void *) -1l;
		  __set_errno (saved_errno);
		}
	    }

	  if (ni->library->lib_handle == (void *) -1l)
	    /* Library not found => function not found.  */
	    result = NULL;
	  else
	    {
	      /* Get the desired function.  Again,  GNU ld.so magic ahead.  */
	      size_t namlen = (5 + strlen (ni->library->name) + 1
			       + strlen (fct_name) + 1);
	      struct get_sym_args args;
	      args.name = __alloca (namlen);
	      args.map = ni->library->lib_handle;

	      /* Construct the function name.  */
	      __stpcpy (__stpcpy (__stpcpy (__stpcpy (args.name, "_nss_"),
					    ni->library->name),
				  "_"),
			fct_name);

	      /* Look up the symbol.  */
	      result = (nss_dlerror_run (get_sym, &args) ? NULL
			: (void *) (args.loadbase + args.ref->st_value));
	    }
#else
	  /* We can't get function address dynamically in static linking. */
	  {
# define DEFINE_ENT(h,nm)						      \
	    extern void _nss_##h##_get##nm##ent_r (void);		      \
	    extern void _nss_##h##_end##nm##ent (void);			      \
	    extern void _nss_##h##_set##nm##ent (void);
# define DEFINE_GET(h,nm)						      \
	    extern void _nss_##h##_get##nm##_r (void);
# define DEFINE_GETBY(h,nm,ky)						      \
	    extern void _nss_##h##_get##nm##by##ky##_r (void);
# include "function.def"
# undef DEFINE_ENT
# undef DEFINE_GET
# undef DEFINE_GETBY
# define DEFINE_ENT(h,nm)						      \
	    { #h"_get"#nm"ent_r", _nss_##h##_get##nm##ent_r },		      \
	    { #h"_end"#nm"ent", _nss_##h##_end##nm##ent },		      \
	    { #h"_set"#nm"ent", _nss_##h##_set##nm##ent },
# define DEFINE_GET(h,nm)						      \
	    { #h"_get"#nm"_r", _nss_##h##_get##nm##_r },
# define DEFINE_GETBY(h,nm,ky)						      \
	    { #h"_get"#nm"by"#ky"_r", _nss_##h##_get##nm##by##ky##_r },
	    static struct fct_tbl { const char *fname; void *fp; } *tp, tbl[] =
	      {
# include "function.def"
		{ NULL, NULL }
	      };
	    size_t namlen = (5 + strlen (ni->library->name) + 1
			     + strlen (fct_name) + 1);
	    char name[namlen];

	    /* Construct the function name.  */
	    __stpcpy (__stpcpy (__stpcpy (name, ni->library->name),
				"_"),
		      fct_name);

	    result = NULL;
	    for (tp = &tbl[0]; tp->fname; tp++)
	      if (strcmp (tp->fname, name) == 0)
		{
		  result = tp->fp;
		  break;
		}
	  }
#endif

	  /* Remember function pointer for later calls.  Even if null, we
	     record it so a second try needn't search the library again.  */
	  known->fct_ptr = result;
	}
    }

  /* Remove the lock.  */
  __libc_lock_unlock (lock);

  return result;
}


static name_database *
internal_function
nss_parse_file (const char *fname)
{
  FILE *fp;
  name_database *result;
  name_database_entry *last;
  char *line;
  size_t len;

  /* Open the configuration file.  */
  fp = fopen (fname, "r");
  if (fp == NULL)
    return NULL;

  result = (name_database *) malloc (sizeof (name_database));
  if (result == NULL)
    return NULL;

  result->entry = NULL;
  result->library = NULL;
  last = NULL;
  line = NULL;
  len = 0;
  do
    {
      name_database_entry *this;
      ssize_t n;

      n = __getline (&line, &len, fp);
      if (n < 0)
	break;
      if (line[n - 1] == '\n')
	line[n - 1] = '\0';

      /* Because the file format does not know any form of quoting we
	 can search forward for the next '#' character and if found
	 make it terminating the line.  */
      *__strchrnul (line, '#') = '\0';

      /* If the line is blank it is ignored.  */
      if (line[0] == '\0')
	continue;

      /* Each line completely specifies the actions for a database.  */
      this = nss_getline (line);
      if (this != NULL)
	{
	  if (last != NULL)
	    last->next = this;
	  else
	    result->entry = this;

	  last = this;
	}
    }
  while (!feof_unlocked (fp));

  /* Free the buffer.  */
  free (line);
  /* Close configuration file.  */
  fclose (fp);

  return result;
}


/* Read the source names:
	`( <source> ( "[" "!"? (<status> "=" <action> )+ "]" )? )*'
   */
static service_user *
internal_function
nss_parse_service_list (const char *line)
{
  service_user *result = NULL, **nextp = &result;

  while (1)
    {
      service_user *new_service;
      const char *name;

      while (isspace (line[0]))
	++line;
      if (line[0] == '\0')
	/* No source specified.  */
	return result;

      /* Read <source> identifier.  */
      name = line;
      while (line[0] != '\0' && !isspace (line[0]) && line[0] != '[')
	++line;
      if (name == line)
	return result;


      new_service = (service_user *) malloc (sizeof (service_user)
					     + (line - name + 1));
      if (new_service == NULL)
	return result;

      *((char *) __mempcpy (new_service->name, name, line - name)) = '\0';

      /* Set default actions.  */
      new_service->actions[2 + NSS_STATUS_TRYAGAIN] = NSS_ACTION_CONTINUE;
      new_service->actions[2 + NSS_STATUS_UNAVAIL] = NSS_ACTION_CONTINUE;
      new_service->actions[2 + NSS_STATUS_NOTFOUND] = NSS_ACTION_CONTINUE;
      new_service->actions[2 + NSS_STATUS_SUCCESS] = NSS_ACTION_RETURN;
      new_service->actions[2 + NSS_STATUS_RETURN] = NSS_ACTION_RETURN;
      new_service->library = NULL;
      new_service->known = NULL;
      new_service->next = NULL;

      while (isspace (line[0]))
	++line;

      if (line[0] == '[')
	{
	  /* Read criterions.  */
	  do
	    ++line;
	  while (line[0] != '\0' && isspace (line[0]));

	  do
	    {
	      int not;
	      enum nss_status status;
	      lookup_actions action;

	      /* Grok ! before name to mean all statii but that one.  */
	      not = line[0] == '!';
	      if (not)
		++line;

	      /* Read status name.  */
	      name = line;
	      while (line[0] != '\0' && !isspace (line[0]) && line[0] != '='
		     && line[0] != ']')
		++line;

	      /* Compare with known statii.  */
	      if (line - name == 7)
		{
		  if (__strncasecmp (name, "SUCCESS", 7) == 0)
		    status = NSS_STATUS_SUCCESS;
		  else if (__strncasecmp (name, "UNAVAIL", 7) == 0)
		    status = NSS_STATUS_UNAVAIL;
		  else
		    return result;
		}
	      else if (line - name == 8)
		{
		  if (__strncasecmp (name, "NOTFOUND", 8) == 0)
		    status = NSS_STATUS_NOTFOUND;
		  else if (__strncasecmp (name, "TRYAGAIN", 8) == 0)
		    status = NSS_STATUS_TRYAGAIN;
		  else
		    return result;
		}
	      else
		return result;

	      while (isspace (line[0]))
		++line;
	      if (line[0] != '=')
		return result;
	      do
		++line;
	      while (isspace (line[0]));

	      name = line;
	      while (line[0] != '\0' && !isspace (line[0]) && line[0] != '='
		     && line[0] != ']')
		++line;

	      if (line - name == 6 && __strncasecmp (name, "RETURN", 6) == 0)
		action = NSS_ACTION_RETURN;
	      else if (line - name == 8
		       && __strncasecmp (name, "CONTINUE", 8) == 0)
		action = NSS_ACTION_CONTINUE;
	      else
		return result;

	      if (not)
		{
		  /* Save the current action setting for this status,
		     set them all to the given action, and reset this one.  */
		  const lookup_actions save = new_service->actions[2 + status];
		  new_service->actions[2 + NSS_STATUS_TRYAGAIN] = action;
		  new_service->actions[2 + NSS_STATUS_UNAVAIL] = action;
		  new_service->actions[2 + NSS_STATUS_NOTFOUND] = action;
		  new_service->actions[2 + NSS_STATUS_SUCCESS] = action;
		  new_service->actions[2 + status] = save;
		}
	      else
		new_service->actions[2 + status] = action;

	      /* Skip white spaces.  */
	      while (isspace (line[0]))
		++line;
	    }
	  while (line[0] != ']');

	  /* Skip the ']'.  */
	  ++line;
	}

      *nextp = new_service;
      nextp = &new_service->next;
    }
}

static name_database_entry *
internal_function
nss_getline (char *line)
{
  const char *name;
  name_database_entry *result;
  size_t len;

  /* Ignore leading white spaces.  ATTENTION: this is different from
     what is implemented in Solaris.  The Solaris man page says a line
     beginning with a white space character is ignored.  We regard
     this as just another misfeature in Solaris.  */
  while (isspace (line[0]))
    ++line;

  /* Recognize `<database> ":"'.  */
  name = line;
  while (line[0] != '\0' && !isspace (line[0]) && line[0] != ':')
    ++line;
  if (line[0] == '\0' || name == line)
    /* Syntax error.  */
    return NULL;
  *line++ = '\0';

  len = strlen (name) + 1;

  result = (name_database_entry *) malloc (sizeof (name_database_entry) + len);
  if (result == NULL)
    return NULL;

  /* Save the database name.  */
  memcpy (result->name, name, len);

  /* Parse the list of services.  */
  result->service = nss_parse_service_list (line);

  result->next = NULL;
  return result;
}


static service_library *
internal_function
nss_new_service (name_database *database, const char *name)
{
  service_library **currentp = &database->library;

  while (*currentp != NULL)
    {
      if (strcmp ((*currentp)->name, name) == 0)
	return *currentp;
      currentp = &(*currentp)->next;
    }

  /* We have to add the new service.  */
  *currentp = (service_library *) malloc (sizeof (service_library));
  if (*currentp == NULL)
    return NULL;

  (*currentp)->name = name;
  (*currentp)->lib_handle = NULL;
  (*currentp)->next = NULL;

  return *currentp;
}
