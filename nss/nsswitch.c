/* Copyright (C) 1996 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <ctype.h>
#include <dlfcn.h>
#include <netdb.h>
#include <libc-lock.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsswitch.h"
#include "../elf/link.h"	/* We need some help from ld.so.  */

/* Prototypes for the local functions.  */
static void nss_init (void);
static void *nss_lookup_function (service_user *ni, const char *fct_name);
static int nss_find_entry (struct entry **knownp, const char *key,
			   void **valp);
static void nss_insert_entry (struct entry **knownp, const char *key,
			      void *val);
static name_database *nss_parse_file (const char *fname);
static name_database_entry *nss_getline (char *line);
static service_user *nss_parse_service_list (const char *line);
static service_library *nss_new_service (name_database *database,
					 const char *name);


__libc_lock_define_initialized (static, lock);


/* Global variable.  */
struct __res_state _res;


/* Nonzero if the sevices are already initialized.  */
static int nss_initialized;


/* The root of the whole data base.  */
static name_database *service_table;


static void
nss_init (void)
{
  /* Prevent multiple threads to change the service table.  */
  __libc_lock_lock (lock);

  if (service_table == NULL)
    service_table = nss_parse_file (_PATH_NSSWITCH_CONF);

  __libc_lock_unlock (lock);
}


/* -1 == database not found
    0 == database entry pointer stored */
int
__nss_database_lookup (const char *database, const char *defconfig,
		       service_user **ni)
{
  name_database_entry *entry;

  if (nss_initialized == 0)
    nss_init ();

  /* Test whether configuration data is available.  */
  if (service_table)
    {
      /* Return first `service_user' entry for DATABASE.
	 XXX Will use perfect hashing function for known databases.  */

      /* XXX Could use some faster mechanism here.  But each database is
	 only requested once and so this might not be critical.  */
      for (entry = service_table->entry; entry != NULL; entry = entry->next)
	if (strcmp (database, entry->name) == 0)
	  {
	    *ni = entry->service;
	    return 0;
	  }
    }

  /* No configuration data is available, either because nsswitch.conf
     doesn't exist or because it doesn't have a line for this database.  */
  entry = malloc (sizeof *entry);
  if (entry == NULL)
    return -1;
  entry->name = database;
  /* DEFCONFIG specifies the default service list for this database,
     or null to use the most common default.  */
  entry->service = nss_parse_service_list (defconfig ?:
					   "compat [NOTFOUND=return] files");

  *ni = entry->service;
  return 0;
}


/* -1 == not found
    0 == adjusted for next function */
int
__nss_lookup (service_user **ni, const char *fct_name, void **fctp)
{
  *fctp = nss_lookup_function (*ni, fct_name);

  while (*fctp == NULL
	 && nss_next_action (*ni, NSS_STATUS_UNAVAIL) == NSS_ACTION_CONTINUE
	 && (*ni)->next != NULL)
    {
      *ni = (*ni)->next;

      *fctp = nss_lookup_function (*ni, fct_name);
    }

  return *fctp != NULL ? 0 : -1;
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
       if (NSS_STATUS_TRYAGAIN > status || status > NSS_STATUS_SUCCESS)
	 __libc_fatal ("illegal status in " __FUNCTION__);

       if (nss_next_action (*ni, status) == NSS_ACTION_RETURN)
	 return 1;
    }

  if ((*ni)->next == NULL)
    return -1;

  do
    {
      *ni = (*ni)->next;

      *fctp = nss_lookup_function (*ni, fct_name);
    }
  while (*fctp == NULL
	 && nss_next_action (*ni, NSS_STATUS_UNAVAIL) == NSS_ACTION_CONTINUE
	 && (*ni)->next != NULL);

  return *fctp != NULL ? 0 : -1;
}


static int
nss_dlerror_run (void (*operate) (void))
{
  const char *last_errstring = NULL;
  const char *last_object_name = NULL;

  (void) _dl_catch_error (&last_errstring, &last_object_name, operate);

  return last_errstring != NULL;
}


static void *
nss_lookup_function (service_user *ni, const char *fct_name)
{
  void *result;

  /* Determine whether current function is loaded.  */
  if (nss_find_entry (&ni->known, fct_name, &result) >= 0)
    return result;

  /* We now modify global data.  Protect it.  */
  __libc_lock_lock (lock);

  if (ni->library == NULL)
    {
      /* This service has not yet been used.  Fetch the service library
	 for it, creating a new one if need be.  If there is no service
	 table from the file, this static variable holds the head of the
	 service_library list made from the default configuration.  */
      static name_database default_table;
      ni->library = nss_new_service (service_table ?: &default_table,
				     ni->name);
      if (ni->library == NULL)
	{
	  /* This only happens when out of memory.  */
	  __libc_lock_unlock (lock);
	  return NULL;
	}
    }

  if (ni->library->lib_handle == NULL)
    {
      /* Load the shared library.  */
      size_t shlen = (7 + strlen (ni->library->name) + 3
		      + sizeof (NSS_SHLIB_REVISION));
      char shlib_name[shlen];

      void do_open (void)
	{
	  /* Open and relocate the shared object.  */
	  ni->library->lib_handle = _dl_open (shlib_name, RTLD_LAZY);
	}

      /* Construct name.  */
      __stpcpy (__stpcpy (__stpcpy (shlib_name, "libnss_"), ni->library->name),
		".so" NSS_SHLIB_REVISION);

      if (nss_dlerror_run (do_open) != 0)
	/* Failed to load the library.  */
	ni->library->lib_handle = (void *) -1;
    }

  if (ni->library->lib_handle == (void *) -1)
    /* Library not found => function not found.  */
    result = NULL;
  else
    {
      /* Get the desired function.  Again,  GNU ld.so magic ahead.  */
      size_t namlen = (5 + strlen (ni->library->name) + 1
		       + strlen (fct_name) + 1);
      char name[namlen];
      struct link_map *map = ni->library->lib_handle;
      Elf32_Addr loadbase;
      const Elf32_Sym *ref = NULL;
      void get_sym (void)
	{
	  struct link_map *scope[2] = { map, NULL };
	  loadbase = _dl_lookup_symbol (name, &ref, scope, map->l_name, 0, 0);
	}

      __stpcpy (__stpcpy (__stpcpy (__stpcpy (name, "_nss_"),
				    ni->library->name),
			  "_"),
		fct_name);

      result = (nss_dlerror_run (get_sym)
		? NULL : (void *) (loadbase + ref->st_value));
    }

  /* Remember function pointer for the usage.  */
  nss_insert_entry (&ni->known, fct_name, result);

  /* Remove the lock.  */
  __libc_lock_unlock (lock);

  return result;
}


static int
known_compare (const void *p1, const void *p2)
{
  known_function *v1 = (known_function *) p1;
  known_function *v2 = (known_function *) p2;

  return strcmp (v1->fct_name, v2->fct_name);
}


static int
nss_find_entry (struct entry **knownp, const char *key, void **valp)
{
  known_function looking_for = { fct_name: key };
  struct entry **found;

  found = __tfind (&looking_for, (const void **) knownp, known_compare);

  if (found == NULL)
    return -1;

  *valp = ((known_function *) (*found)->key)->fct_ptr;

  return 0;
}


static void
nss_insert_entry (struct entry **knownp, const char *key, void *val)
{
  known_function *to_insert;

  to_insert = (known_function *) malloc (sizeof (known_function));
  if (to_insert == NULL)
    return;

  to_insert->fct_name = key;
  to_insert->fct_ptr = val;

  __tsearch (to_insert, (void **) knownp, known_compare);
}


static name_database *
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
      char *cp;

      n = __getline (&line, &len, fp);
      if (n < 0)
	break;
      if (line[n - 1] == '\n')
	line[n - 1] = '\0';

      /* Because the file format does not know any form of quoting we
	 can search forward for the next '#' character and if found
	 make it terminating the line.  */
      cp = strchr (line, '#');
      if (cp != NULL)
	*cp = '\0';

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
  while (!feof (fp));

  /* Free the buffer.  */
  free (line);
  /* Close configuration file.  */
  fclose (fp);

  return result;
}


/* Read the source names: `<source> ( "[" <status> "=" <action> "]" )*'.  */
static service_user *
nss_parse_service_list (const char *line)
{
  service_user *result = NULL, **nextp = &result;

  while (1)
    {
      service_user *new_service;
      char *name;

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


      new_service = (service_user *) malloc (sizeof (service_user));
      if (new_service == NULL)
	return result;
      else
	{
	  char *source = (char *) malloc (line - name + 1);
	  if (source == NULL)
	    {
	      free (new_service);
	      return result;
	    }
	  memcpy (source, name, line - name);
	  source[line - name] = '\0';

	  new_service->name = source;
	}

      /* Set default actions.  */
      new_service->actions[2 + NSS_STATUS_TRYAGAIN] = NSS_ACTION_CONTINUE;
      new_service->actions[2 + NSS_STATUS_UNAVAIL] = NSS_ACTION_CONTINUE;
      new_service->actions[2 + NSS_STATUS_NOTFOUND] = NSS_ACTION_CONTINUE;
      new_service->actions[2 + NSS_STATUS_SUCCESS] = NSS_ACTION_RETURN;
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
	      if (not = line[0] == '!')
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
nss_getline (char *line)
{
  const char *name;
  name_database_entry *result;

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

  result = (name_database_entry *) malloc (sizeof (name_database_entry));
  if (result == NULL)
    return NULL;

  /* Save the database name.  */
  {
    const size_t len = strlen (name) + 1;
    char *new = malloc (len);
    if (new == NULL)
      {
	free (result);
	return NULL;
      }
    result->name = memcpy (new, name, len);
  }

  /* Parse the list of services.  */
  result->service = nss_parse_service_list (line);

  result->next = NULL;
  return result;
}


static service_library *
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
