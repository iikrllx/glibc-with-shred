/* Handle configuration data.
   Copyright (C) 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <search.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#include <bits/libc-lock.h>
#include <gconv_int.h>


/* This is the default path where we look for module lists.  */
static const char default_gconv_path[] = GCONV_PATH;

/* The path elements, as determined by the __gconv_get_path function.
   All path elements end in a slash.  */
struct path_elem *__gconv_path_elem;
/* Maximum length of a single path element in __gconv_path_elem.  */
size_t __gconv_max_path_elem_len;

/* We use the following struct if we couldn't allocate memory.  */
static const struct path_elem empty_path_elem;

/* Name of the file containing the module information in the directories
   along the path.  */
static const char gconv_conf_filename[] = "gconv-modules";

/* Filename extension for the modules.  */
#ifndef MODULE_EXT
# define MODULE_EXT ".so"
#endif
static const char gconv_module_ext[] = MODULE_EXT;

/* We have a few builtin transformations.  */
static struct gconv_module builtin_modules[] =
{
#define BUILTIN_TRANSFORMATION(From, To, Cost, Name, Fct, Init, End, MinF, \
			       MaxF, MinT, MaxT) \
  {									      \
    from_string: From,							      \
    to_string: To,							      \
    cost_hi: Cost,							      \
    cost_lo: INT_MAX,							      \
    module_name: Name							      \
  },
#define BUILTIN_ALIAS(From, To)

#include "gconv_builtin.h"
};

#undef BUILTIN_TRANSFORMATION
#undef BUILTIN_ALIAS

static const char *builtin_aliases[] =
{
#define BUILTIN_TRANSFORMATION(From, To, Cost, Name, Fct, Init, End, MinF, \
			       MaxF, MinT, MaxT)
#define BUILTIN_ALIAS(From, To) From " " To,

#include "gconv_builtin.h"
};

#ifdef USE_IN_LIBIO
# include <libio/libioP.h>
# define __getdelim(line, len, c, fp) _IO_getdelim (line, len, c, fp)
#endif


/* Test whether there is already a matching module known.  */
static int
internal_function
detect_conflict (const char *alias)
{
  struct gconv_module *node = __gconv_modules_db;

  while (node != NULL)
    {
      int cmpres = strcmp (alias, node->from_string);

      if (cmpres == 0)
	/* We have a conflict.  */
	return 1;
      else if (cmpres < 0)
	node = node->left;
      else
	node = node->right;
    }

  return node != NULL;
}


/* Add new alias.  */
static inline void
add_alias (char *rp, void *modules)
{
  /* We now expect two more string.  The strings are normalized
     (converted to UPPER case) and strored in the alias database.  */
  struct gconv_alias *new_alias;
  char *from, *to, *wp;

  while (isspace (*rp))
    ++rp;
  from = wp = rp;
  while (*rp != '\0' && !isspace (*rp))
    *wp++ = toupper (*rp++);
  if (*rp == '\0')
    /* There is no `to' string on the line.  Ignore it.  */
    return;
  *wp++ = '\0';
  to = ++rp;
  while (isspace (*rp))
    ++rp;
  while (*rp != '\0' && !isspace (*rp))
    *wp++ = toupper (*rp++);
  if (to == wp)
    /* No `to' string, ignore the line.  */
    return;
  *wp++ = '\0';

  /* Test whether this alias conflicts with any available module.  */
  if (detect_conflict (from))
    /* It does conflict, don't add the alias.  */
    return;

  new_alias = (struct gconv_alias *)
    malloc (sizeof (struct gconv_alias) + (wp - from));
  if (new_alias != NULL)
    {
      void **inserted;

      new_alias->fromname = memcpy ((char *) new_alias
				    + sizeof (struct gconv_alias),
				    from, wp - from);
      new_alias->toname = new_alias->fromname + (to - from);

      inserted = (void **) __tsearch (new_alias, &__gconv_alias_db,
				      __gconv_alias_compare);
      if (inserted == NULL || *inserted != new_alias)
	/* Something went wrong, free this entry.  */
	free (new_alias);
    }
}


/* Insert a data structure for a new module in the search tree.  */
static inline void
internal_function
insert_module (struct gconv_module *newp, int tobefreed)
{
  struct gconv_module **rootp = &__gconv_modules_db;

  while (*rootp != NULL)
    {
      struct gconv_module *root = *rootp;
      int cmpres;

      cmpres = strcmp (newp->from_string, root->from_string);
      if (cmpres == 0)
	{
	  /* Both strings are identical.  Insert the string at the
	     end of the `same' list if it is not already there.  */
	  while (strcmp (newp->from_string, root->from_string) != 0
		 || strcmp (newp->to_string, root->to_string) != 0)
	    {
	      rootp = &root->same;
	      root = *rootp;
	      if (root == NULL)
		break;
	    }

	  if (root != NULL)
	    {
	      /* This is a no new conversion.  But maybe the cost is
		 better.  */
	      if (newp->cost_hi < root->cost_hi
		  || (newp->cost_hi == root->cost_hi
		      && newp->cost_lo < root->cost_lo))
		{
		  root->cost_hi = newp->cost_hi;
		  root->cost_lo = newp->cost_lo;
		  root->module_name = newp->module_name;
		}

	      if (tobefreed)
		free (newp);
	      return;
	    }

	  break;
	}
      else if (cmpres < 0)
	rootp = &root->left;
      else
	rootp = &root->right;
    }

  /* Plug in the new node here.  */
  *rootp = newp;
}


/* Add new module.  */
static void
internal_function
add_module (char *rp, const char *directory, size_t dir_len, void **modules,
	    size_t *nmodules, int modcounter)
{
  /* We expect now
     1. `from' name
     2. `to' name
     3. filename of the module
     4. an optional cost value
  */
  struct gconv_alias fake_alias;
  struct gconv_module *new_module;
  char *from, *to, *module, *wp;
  int need_ext;
  int cost_hi;

  while (isspace (*rp))
    ++rp;
  from = rp;
  while (*rp != '\0' && !isspace (*rp))
    {
      *rp = toupper (*rp);
      ++rp;
    }
  if (*rp == '\0')
    return;
  *rp++ = '\0';
  to = wp = rp;
  while (isspace (*rp))
    ++rp;
  while (*rp != '\0' && !isspace (*rp))
    *wp++ = toupper (*rp++);
  if (*rp == '\0')
    return;
  *wp++ = '\0';
  do
    ++rp;
  while (isspace (*rp));
  module = wp;
  while (*rp != '\0' && !isspace (*rp))
    *wp++ = *rp++;
  if (*rp == '\0')
    {
      /* There is no cost, use one by default.  */
      *wp++ = '\0';
      cost_hi = 1;
    }
  else
    {
      /* There might be a cost value.  */
      char *endp;

      *wp++ = '\0';
      cost_hi = strtol (rp, &endp, 10);
      if (rp == endp || cost_hi < 1)
	/* No useful information.  */
	cost_hi = 1;
    }

  if (module[0] == '\0')
    /* No module name given.  */
    return;
  if (module[0] == '/')
    dir_len = 0;

  /* See whether we must add the ending.  */
  need_ext = 0;
  if (wp - module < (ptrdiff_t) sizeof (gconv_module_ext)
      || memcmp (wp - sizeof (gconv_module_ext), gconv_module_ext,
		 sizeof (gconv_module_ext)) != 0)
    /* We must add the module extension.  */
    need_ext = sizeof (gconv_module_ext) - 1;

  /* See whether we have already an alias with this name defined.  */
  fake_alias.fromname = strndupa (from, to - from);

  if (__tfind (&fake_alias, &__gconv_alias_db, __gconv_alias_compare) != NULL)
    /* This module duplicates an alias.  */
    return;

  new_module = (struct gconv_module *) calloc (1,
					       sizeof (struct gconv_module)
					       + (wp - from)
					       + dir_len + need_ext);
  if (new_module != NULL)
    {
      char *tmp;

      new_module->from_string = tmp = (char *) (new_module + 1);
      tmp = __mempcpy (tmp, from, to - from);

      new_module->to_string = tmp;
      tmp = __mempcpy (tmp, to, module - to);

      new_module->cost_hi = cost_hi;
      new_module->cost_lo = modcounter;

      new_module->module_name = tmp;

      if (dir_len != 0)
	tmp = __mempcpy (tmp, directory, dir_len);

      tmp = __mempcpy (tmp, module, wp - module);

      if (need_ext)
	memcpy (tmp - 1, gconv_module_ext, sizeof (gconv_module_ext));

      /* Now insert the new module data structure in our search tree.  */
      insert_module (new_module, 1);
    }
}


/* Read the next configuration file.  */
static void
internal_function
read_conf_file (const char *filename, const char *directory, size_t dir_len,
		void **modules, size_t *nmodules)
{
  FILE *fp = fopen (filename, "r");
  char *line = NULL;
  size_t line_len = 0;
  int modcounter = 0;

  /* Don't complain if a file is not present or readable, simply silently
     ignore it.  */
  if (fp == NULL)
    return;

  /* Process the known entries of the file.  Comments start with `#' and
     end with the end of the line.  Empty lines are ignored.  */
  while (!feof_unlocked (fp))
    {
      char *rp, *endp, *word;
      ssize_t n = __getdelim (&line, &line_len, '\n', fp);
      if (n < 0)
	/* An error occurred.  */
	break;

      rp = line;
      /* Terminate the line (excluding comments or newline) by an NUL byte
	 to simplify the following code.  */
      endp = strchr (rp, '#');
      if (endp != NULL)
	*endp = '\0';
      else
	if (rp[n - 1] == '\n')
	  rp[n - 1] = '\0';

      while (isspace (*rp))
	++rp;

      /* If this is an empty line go on with the next one.  */
      if (rp == endp)
	continue;

      word = rp;
      while (*rp != '\0' && !isspace (*rp))
	++rp;

      if (rp - word == sizeof ("alias") - 1
	  && memcmp (word, "alias", sizeof ("alias") - 1) == 0)
	add_alias (rp, *modules);
      else if (rp - word == sizeof ("module") - 1
	       && memcmp (word, "module", sizeof ("module") - 1) == 0)
	add_module (rp, directory, dir_len, modules, nmodules, modcounter++);
      /* else */
	/* Otherwise ignore the line.  */
    }

  free (line);

  fclose (fp);
}


/* Determine the directories we are looking for data in.  */
void
__gconv_get_path (void)
{
  struct path_elem *result;
  __libc_lock_define_initialized (static, lock);

  __libc_lock_lock (lock);

  /* Make sure there wasn't a second thread doing it already.  */
  result = (struct path_elem *) __gconv_path_elem;
  if (result == NULL)
    {
      /* Determine the complete path first.  */
      const char *user_path;
      char *gconv_path;
      size_t gconv_path_len;
      char *elem;
      char *oldp;
      char *cp;
      int nelems;
      char *cwd;
      size_t cwdlen;

      user_path = getenv ("GCONV_PATH");
      if (user_path == NULL)
	{
	  /* No user-defined path.  Make a modifiable copy of the
	     default path.  */
	  gconv_path = strdupa (default_gconv_path);
	  gconv_path_len = sizeof (default_gconv_path);
	  cwd = NULL;
	  cwdlen = 0;
	}
      else
	{
	  /* Append the default path to the user-defined path.  */
	  size_t user_len = strlen (user_path);

	  gconv_path_len = user_len + 1 + sizeof (default_gconv_path);
	  gconv_path = alloca (gconv_path_len);
	  __mempcpy (__mempcpy (__mempcpy (gconv_path, user_path, user_len),
				":", 1),
		     default_gconv_path, sizeof (default_gconv_path));
	  cwd = __getcwd (NULL, 0);
	  cwdlen = strlen (cwd);
	}
      assert (default_gconv_path[0] == '/');

      /* In a first pass we calculate the number of elements.  */
      oldp = NULL;
      cp = strchr (gconv_path, ':');
      nelems = 1;
      while (cp != NULL)
	{
	  if (cp != oldp + 1)
	    ++nelems;
	  oldp = cp;
	  cp =  strchr (cp + 1, ':');
	}

      /* Allocate the memory for the result.  */
      result = (struct path_elem *) malloc ((nelems + 1)
					    * sizeof (struct path_elem)
					    + gconv_path_len + nelems
					    + (nelems - 1) * (cwdlen + 1));
      if (result != NULL)
	{
	  char *strspace = (char *) &result[nelems + 1];
	  int n = 0;

	  /* Separate the individual parts.  */
	  __gconv_max_path_elem_len = 0;
	  elem = __strtok_r (gconv_path, ":", &gconv_path);
	  assert (elem != NULL);
	  do
	    {
	      result[n].name = strspace;
	      if (elem[0] != '/')
		{
		  assert (cwd != NULL);
		  strspace = __mempcpy (strspace, cwd, cwdlen);
		  *strspace++ = '/';
		}
	      strspace = __stpcpy (strspace, elem);
	      if (strspace[-1] != '/')
		*strspace++ = '/';

	      result[n].len = strspace - result[n].name;
	      if (result[n].len > __gconv_max_path_elem_len)
		__gconv_max_path_elem_len = result[n].len;

	      *strspace++ = '\0';
	      ++n;
	    }
	  while ((elem = __strtok_r (NULL, ":", &gconv_path)) != NULL);

	  result[n].name = NULL;
	  result[n].len = 0;
	}

      __gconv_path_elem = result ?: &empty_path_elem;

      if (cwd != NULL)
	free (cwd);
    }

  __libc_lock_unlock (lock);
}


/* Read all configuration files found in the user-specified and the default
   path.  */
void
__gconv_read_conf (void)
{
  void *modules = NULL;
  size_t nmodules = 0;
  int save_errno = errno;
  size_t cnt;

  /* Find out where we have to look.  */
  if (__gconv_path_elem == NULL)
    __gconv_get_path ();

  for (cnt = 0; __gconv_path_elem[cnt].name != NULL; ++cnt)
    {
      const char *elem = __gconv_path_elem[cnt].name;
      size_t elem_len = __gconv_path_elem[cnt].len;
      char *filename;

      /* No slash needs to be inserted between elem and gconv_conf_filename;
	 elem already ends in a slash.  */
      filename = alloca (elem_len + sizeof (gconv_conf_filename));
      __mempcpy (__mempcpy (filename, elem, elem_len),
		 gconv_conf_filename, sizeof (gconv_conf_filename));

      /* Read the next configuration file.  */
      read_conf_file (filename, elem, elem_len, &modules, &nmodules);
    }

  /* Add the internal modules.  */
  for (cnt = 0; cnt < sizeof (builtin_modules) / sizeof (builtin_modules[0]);
       ++cnt)
    {
      struct gconv_alias fake_alias;

      fake_alias.fromname = builtin_modules[cnt].from_string;

      if (__tfind (&fake_alias, &__gconv_alias_db, __gconv_alias_compare)
	  != NULL)
	/* It'll conflict so don't add it.  */
	continue;

      insert_module (&builtin_modules[cnt], 0);
    }

  /* Add aliases for builtin conversions.  */
  cnt = sizeof (builtin_aliases) / sizeof (builtin_aliases[0]);
  while (cnt > 0)
    {
      char *copy = strdupa (builtin_aliases[--cnt]);
      add_alias (copy, modules);
    }

  /* Restore the error number.  */
  __set_errno (save_errno);
}



/* Free all resources if necessary.  */
static void __attribute__ ((unused))
free_mem (void)
{
  if (__gconv_path_elem != NULL && __gconv_path_elem != &empty_path_elem)
    free ((void *) __gconv_path_elem);
}

text_set_element (__libc_subfreeres, free_mem);
