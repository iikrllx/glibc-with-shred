/* Implementation of the internal dcigettext function.
   Copyright (C) 1995-1999, 2000 Free Software Foundation, Inc.

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

/* Tell glibc's <string.h> to provide a prototype for mempcpy().
   This must come before <config.h> because <config.h> may include
   <features.h>, and once <features.h> has been included, it's too late.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#if defined __GNUC__ && !defined C_ALLOCA
# define alloca __builtin_alloca
# define HAVE_ALLOCA 1
#else
# if (defined HAVE_ALLOCA_H || defined _LIBC) && !defined C_ALLOCA
#  include <alloca.h>
# else
#  ifdef _AIX
 #pragma alloca
#  else
#   ifndef alloca
char *alloca ();
#   endif
#  endif
# endif
#endif

#include <errno.h>
#ifndef errno
extern int errno;
#endif
#ifndef __set_errno
# define __set_errno(val) errno = (val)
#endif

#if defined STDC_HEADERS || defined _LIBC
# include <stdlib.h>
#else
char *getenv ();
# ifdef HAVE_MALLOC_H
#  include <malloc.h>
# else
void free ();
# endif
#endif

#if defined HAVE_STRING_H || defined _LIBC
# include <string.h>
#else
# include <strings.h>
#endif
#if !HAVE_STRCHR && !defined _LIBC
# ifndef strchr
#  define strchr index
# endif
#endif

#if defined HAVE_UNISTD_H || defined _LIBC
# include <unistd.h>
#endif

#if defined HAVE_LOCALE_H || defined _LIBC
# include <locale.h>
#endif

#if defined HAVE_SYS_PARAM_H || defined _LIBC
# include <sys/param.h>
#endif

#include "gettext.h"
#include "gettextP.h"
#ifdef _LIBC
# include <libintl.h>
#else
# include "libgettext.h"
#endif
#include "hash-string.h"

/* Thread safetyness.  */
#ifdef _LIBC
# include <bits/libc-lock.h>
#else
/* Provide dummy implementation if this is outside glibc.  */
# define __libc_lock_define_initialized(CLASS, NAME)
# define __libc_lock_lock(NAME)
# define __libc_lock_unlock(NAME)
# define __libc_rwlock_define_initialized(CLASS, NAME)
# define __libc_rwlock_rdlock(NAME)
# define __libc_rwlock_unlock(NAME)
#endif

/* @@ end of prolog @@ */

#ifdef _LIBC
/* Rename the non ANSI C functions.  This is required by the standard
   because some ANSI C functions will require linking with this object
   file and the name space must not be polluted.  */
# define getcwd __getcwd
# ifndef stpcpy
#  define stpcpy __stpcpy
# endif
#else
# if !defined HAVE_GETCWD
char *getwd ();
#  define getcwd(buf, max) getwd (buf)
# else
char *getcwd ();
# endif
# ifndef HAVE_STPCPY
static char *stpcpy PARAMS ((char *dest, const char *src));
# endif
# ifndef HAVE_MEMPCPY
static void *mempcpy PARAMS ((void *dest, const void *src, size_t n));
# endif
#endif

/* Amount to increase buffer size by in each try.  */
#define PATH_INCR 32

/* The following is from pathmax.h.  */
/* Non-POSIX BSD systems might have gcc's limits.h, which doesn't define
   PATH_MAX but might cause redefinition warnings when sys/param.h is
   later included (as on MORE/BSD 4.3).  */
#if defined _POSIX_VERSION || (defined HAVE_LIMITS_H && !defined __GNUC__)
# include <limits.h>
#endif

#ifndef _POSIX_PATH_MAX
# define _POSIX_PATH_MAX 255
#endif

#if !defined PATH_MAX && defined _PC_PATH_MAX
# define PATH_MAX (pathconf ("/", _PC_PATH_MAX) < 1 ? 1024 : pathconf ("/", _PC_PATH_MAX))
#endif

/* Don't include sys/param.h if it already has been.  */
#if defined HAVE_SYS_PARAM_H && !defined PATH_MAX && !defined MAXPATHLEN
# include <sys/param.h>
#endif

#if !defined PATH_MAX && defined MAXPATHLEN
# define PATH_MAX MAXPATHLEN
#endif

#ifndef PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
#endif

/* XPG3 defines the result of `setlocale (category, NULL)' as:
   ``Directs `setlocale()' to query `category' and return the current
     setting of `local'.''
   However it does not specify the exact format.  And even worse: POSIX
   defines this not at all.  So we can use this feature only on selected
   system (e.g. those using GNU C Library).  */
#ifdef _LIBC
# define HAVE_LOCALE_NULL
#endif

/* We want to allocate a string at the end of the struct.  gcc makes
   this easy.  */
#ifdef __GNUC__
# define ZERO 0
#else
# define ZERO 1
#endif

/* This is the type used for the search tree where known translations
   are stored.  */
struct known_translation_t
{
  /* Domain in which to search.  */
  char *domain;

  /* Plural index.  */
  unsigned long int plindex;

  /* The category.  */
  int category;

  /* State of the catalog counter at the point the string was found.  */
  int counter;

  /* And finally the translation.  */
  const char *translation;

  /* Pointer to the string in question.  */
  char msgid[ZERO];
};

/* Root of the search tree with known translations.  We can use this
   only if the system provides the `tsearch' function family.  */
#if defined HAVE_TSEARCH || defined _LIBC
# include <search.h>

static void *root;

# ifdef _LIBC
#  define tsearch __tsearch
# endif

/* Function to compare two entries in the table of known translations.  */
static int
transcmp (const void *p1, const void *p2)
{
  struct known_translation_t *s1 = (struct known_translation_t *) p1;
  struct known_translation_t *s2 = (struct known_translation_t *) p2;
  int result;

  result = strcmp (s1->msgid, s2->msgid);
  if (result == 0)
    {
      result = strcmp (s1->domain, s2->domain);
      if (result == 0)
	{
	  result = s1->plindex - s2->plindex;
	  if (result == 0)
	    /* We compare the category last (though this is the cheapest
	       operation) since it is hopefully always the same (namely
	       LC_MESSAGES).  */
	    result = s1->category - s2->category;
	}
    }

  return result;
}
#endif

/* Name of the default domain used for gettext(3) prior any call to
   textdomain(3).  The default value for this is "messages".  */
const char _nl_default_default_domain[] = "messages";

/* Value used as the default domain for gettext(3).  */
const char *_nl_current_default_domain = _nl_default_default_domain;

/* Contains the default location of the message catalogs.  */
const char _nl_default_dirname[] = GNULOCALEDIR;

/* List with bindings of specific domains created by bindtextdomain()
   calls.  */
struct binding *_nl_domain_bindings;

/* Prototypes for local functions.  */
static unsigned long int plural_eval (struct expression *pexp,
				      unsigned long int n) internal_function;
static const char *category_to_name PARAMS ((int category)) internal_function;
static const char *guess_category_value PARAMS ((int category,
						 const char *categoryname))
     internal_function;


/* For those loosing systems which don't have `alloca' we have to add
   some additional code emulating it.  */
#ifdef HAVE_ALLOCA
/* Nothing has to be done.  */
# define ADD_BLOCK(list, address) /* nothing */
# define FREE_BLOCKS(list) /* nothing */
#else
struct block_list
{
  void *address;
  struct block_list *next;
};
# define ADD_BLOCK(list, addr)						      \
  do {									      \
    struct block_list *newp = (struct block_list *) malloc (sizeof (*newp));  \
    /* If we cannot get a free block we cannot add the new element to	      \
       the list.  */							      \
    if (newp != NULL) {							      \
      newp->address = (addr);						      \
      newp->next = (list);						      \
      (list) = newp;							      \
    }									      \
  } while (0)
# define FREE_BLOCKS(list)						      \
  do {									      \
    while (list != NULL) {						      \
      struct block_list *old = list;					      \
      list = list->next;						      \
      free (old);							      \
    }									      \
  } while (0)
# undef alloca
# define alloca(size) (malloc (size))
#endif	/* have alloca */


/* Names for the libintl functions are a problem.  They must not clash
   with existing names and they should follow ANSI C.  But this source
   code is also used in GNU C Library where the names have a __
   prefix.  So we have to make a difference here.  */
#ifdef _LIBC
# define DCIGETTEXT __dcigettext
#else
# define DCIGETTEXT dcigettext__
#endif

/* Lock variable to protect the global data in the gettext implementation.  */
__libc_rwlock_define_initialized (, _nl_state_lock)

/* Checking whether the binaries runs SUID must be done and glibc provides
   easier methods therefore we make a difference here.  */
#ifdef _LIBC
# define ENABLE_SECURE __libc_enable_secure
# define DETERMINE_SECURE
#else
static int enable_secure;
# define ENABLE_SECURE (enable_secure == 1)
# define DETERMINE_SECURE \
  if (enable_secure == 0)						      \
    {									      \
      if (getuid () != geteuid () || getgid () != getegid ())		      \
	enable_secure = 1;						      \
      else								      \
	enable_secure = -1;						      \
    }
#endif

/* Look up MSGID in the DOMAINNAME message catalog for the current
   CATEGORY locale and, if PLURAL is nonzero, search over string
   depending on the plural form determined by N.  */
char *
DCIGETTEXT (domainname, msgid1, msgid2, plural, n, category)
     const char *domainname;
     const char *msgid1;
     const char *msgid2;
     int plural;
     unsigned long int n;
     int category;
{
#ifndef HAVE_ALLOCA
  struct block_list *block_list = NULL;
#endif
  struct loaded_l10nfile *domain;
  struct binding *binding;
  const char *categoryname;
  const char *categoryvalue;
  char *dirname, *xdomainname;
  char *single_locale;
  char *retval;
  int saved_errno;
#if defined HAVE_TSEARCH || defined _LIBC
  struct known_translation_t *search;
  struct known_translation_t **foundp = NULL;
  size_t msgid_len;
#endif
  size_t domainname_len;

  /* If no real MSGID is given return NULL.  */
  if (msgid1 == NULL)
    return NULL;

  __libc_rwlock_rdlock (_nl_state_lock);

  /* If DOMAINNAME is NULL, we are interested in the default domain.  If
     CATEGORY is not LC_MESSAGES this might not make much sense but the
     definition left this undefined.  */
  if (domainname == NULL)
    domainname = _nl_current_default_domain;

#if defined HAVE_TSEARCH || defined _LIBC
  msgid_len = strlen (msgid1) + 1;

  if (plural == 0)
    {
      /* Try to find the translation among those which we found at
	 some time.  */
      search = (struct known_translation_t *) alloca (sizeof (*search)
						      + msgid_len);
      memcpy (search->msgid, msgid1, msgid_len);
      search->domain = (char *) domainname;
      search->plindex = 0;
      search->category = category;

      foundp = (struct known_translation_t **) tfind (search, &root, transcmp);
      if (foundp != NULL && (*foundp)->counter == _nl_msg_cat_cntr)
	{
	  __libc_rwlock_unlock (_nl_state_lock);
	  return (char *) (*foundp)->translation;
	}
    }
#endif

  /* Preserve the `errno' value.  */
  saved_errno = errno;

  /* See whether this is a SUID binary or not.  */
  DETERMINE_SECURE;

  /* First find matching binding.  */
  for (binding = _nl_domain_bindings; binding != NULL; binding = binding->next)
    {
      int compare = strcmp (domainname, binding->domainname);
      if (compare == 0)
	/* We found it!  */
	break;
      if (compare < 0)
	{
	  /* It is not in the list.  */
	  binding = NULL;
	  break;
	}
    }

  if (binding == NULL)
    dirname = (char *) _nl_default_dirname;
  else if (binding->dirname[0] == '/')
    dirname = binding->dirname;
  else
    {
      /* We have a relative path.  Make it absolute now.  */
      size_t dirname_len = strlen (binding->dirname) + 1;
      size_t path_max;
      char *ret;

      path_max = (unsigned int) PATH_MAX;
      path_max += 2;		/* The getcwd docs say to do this.  */

      dirname = (char *) alloca (path_max + dirname_len);
      ADD_BLOCK (block_list, dirname);

      __set_errno (0);
      while ((ret = getcwd (dirname, path_max)) == NULL && errno == ERANGE)
	{
	  path_max += PATH_INCR;
	  dirname = (char *) alloca (path_max + dirname_len);
	  ADD_BLOCK (block_list, dirname);
	  __set_errno (0);
	}

      if (ret == NULL)
	{
	  /* We cannot get the current working directory.  Don't signal an
	     error but simply return the default string.  */
	  FREE_BLOCKS (block_list);
	  __set_errno (saved_errno);
	  return (plural == 0
		  ? (char *) msgid1
		  /* Use the Germanic plural rule.  */
		  : n == 1 ? (char *) msgid1 : (char *) msgid2);
	}

      stpcpy (stpcpy (strchr (dirname, '\0'), "/"), binding->dirname);
    }

  /* Now determine the symbolic name of CATEGORY and its value.  */
  categoryname = category_to_name (category);
  categoryvalue = guess_category_value (category, categoryname);

  domainname_len = strlen (domainname);
  xdomainname = (char *) alloca (strlen (categoryname)
				 + domainname_len + 5);
  ADD_BLOCK (block_list, xdomainname);

  stpcpy (mempcpy (stpcpy (stpcpy (xdomainname, categoryname), "/"),
		  domainname, domainname_len),
	  ".mo");

  /* Creating working area.  */
  single_locale = (char *) alloca (strlen (categoryvalue) + 1);
  ADD_BLOCK (block_list, single_locale);


  /* Search for the given string.  This is a loop because we perhaps
     got an ordered list of languages to consider for the translation.  */
  while (1)
    {
      /* Make CATEGORYVALUE point to the next element of the list.  */
      while (categoryvalue[0] != '\0' && categoryvalue[0] == ':')
	++categoryvalue;
      if (categoryvalue[0] == '\0')
	{
	  /* The whole contents of CATEGORYVALUE has been searched but
	     no valid entry has been found.  We solve this situation
	     by implicitly appending a "C" entry, i.e. no translation
	     will take place.  */
	  single_locale[0] = 'C';
	  single_locale[1] = '\0';
	}
      else
	{
	  char *cp = single_locale;
	  while (categoryvalue[0] != '\0' && categoryvalue[0] != ':')
	    *cp++ = *categoryvalue++;
	  *cp = '\0';

	  /* When this is a SUID binary we must not allow accessing files
	     outside the dedicated directories.  */
	  if (ENABLE_SECURE
	      && (memchr (single_locale, '/',
			  _nl_find_language (single_locale) - single_locale)
		  != NULL))
	    /* Ingore this entry.  */
	    continue;
	}

      /* If the current locale value is C (or POSIX) we don't load a
	 domain.  Return the MSGID.  */
      if (strcmp (single_locale, "C") == 0
	  || strcmp (single_locale, "POSIX") == 0)
	{
	  FREE_BLOCKS (block_list);
	  __libc_rwlock_unlock (_nl_state_lock);
	  __set_errno (saved_errno);
	  return (plural == 0
		  ? (char *) msgid1
		  /* Use the Germanic plural rule.  */
		  : n == 1 ? (char *) msgid1 : (char *) msgid2);
	}


      /* Find structure describing the message catalog matching the
	 DOMAINNAME and CATEGORY.  */
      domain = _nl_find_domain (dirname, single_locale, xdomainname, binding);

      if (domain != NULL)
	{
	  unsigned long int index = 0;
#if defined HAVE_TSEARCH || defined _LIBC
	  struct loaded_domain *domaindata =
	    (struct loaded_domain *) domain->data;

	  if (plural != 0)
	    {
	      /* Try to find the translation among those which we
		 found at some time.  */
	      search = (struct known_translation_t *) alloca (sizeof (*search)
							      + msgid_len);
	      memcpy (search->msgid, msgid1, msgid_len);
	      search->domain = (char *) domainname;
	      search->plindex = plural_eval (domaindata->plural, n);
	      if (search->plindex >= domaindata->nplurals)
		/* This should never happen.  It means the plural expression
		   and the given maximum value do not match.  */
		search->plindex = 0;
	      index = search->plindex;
	      search->category = category;

	      foundp = (struct known_translation_t **) tfind (search, &root,
							      transcmp);
	      if (foundp != NULL && (*foundp)->counter == _nl_msg_cat_cntr)
		{
		  __libc_rwlock_unlock (_nl_state_lock);
		  return (char *) (*foundp)->translation;
		}
	    }
#endif

	  retval = _nl_find_msg (domain, msgid1, index);

	  if (retval == NULL)
	    {
	      int cnt;

	      for (cnt = 0; domain->successor[cnt] != NULL; ++cnt)
		{
		  retval = _nl_find_msg (domain->successor[cnt], msgid1,
					 index);

		  if (retval != NULL)
		    break;
		}
	    }

	  if (retval != NULL)
	    {
	      FREE_BLOCKS (block_list);
	      __set_errno (saved_errno);
#if defined HAVE_TSEARCH || defined _LIBC
	      if (foundp == NULL)
		{
		  /* Create a new entry and add it to the search tree.  */
		  struct known_translation_t *newp;

		  newp = (struct known_translation_t *)
		    malloc (sizeof (*newp) + msgid_len
			    + domainname_len + 1 - ZERO);
		  if (newp != NULL)
		    {
		      newp->domain = mempcpy (newp->msgid, msgid1, msgid_len);
		      memcpy (newp->domain, domainname, domainname_len + 1);
		      newp->plindex = index;
		      newp->category = category;
		      newp->counter = _nl_msg_cat_cntr;
		      newp->translation = retval;

		      /* Insert the entry in the search tree.  */
		      foundp = (struct known_translation_t **)
			tsearch (newp, &root, transcmp);
		      if (__builtin_expect (&newp != foundp, 0))
			/* The insert failed.  */
			free (newp);
		    }
		}
	      else
		{
		  /* We can update the existing entry.  */
		  (*foundp)->counter = _nl_msg_cat_cntr;
		  (*foundp)->translation = retval;
		}
#endif
	      __libc_rwlock_unlock (_nl_state_lock);
	      return retval;
	    }
	}
    }
  /* NOTREACHED */
}


char *
internal_function
_nl_find_msg (domain_file, msgid, index)
     struct loaded_l10nfile *domain_file;
     const char *msgid;
     unsigned long int index;
{
  struct loaded_domain *domain;
  size_t act;
  char *result;

  if (domain_file->decided == 0)
    _nl_load_domain (domain_file);

  if (domain_file->data == NULL)
    return NULL;

  domain = (struct loaded_domain *) domain_file->data;

  /* Locate the MSGID and its translation.  */
  if (domain->hash_size > 2 && domain->hash_tab != NULL)
    {
      /* Use the hashing table.  */
      nls_uint32 len = strlen (msgid);
      nls_uint32 hash_val = hash_string (msgid);
      nls_uint32 idx = hash_val % domain->hash_size;
      nls_uint32 incr = 1 + (hash_val % (domain->hash_size - 2));
      nls_uint32 nstr = W (domain->must_swap, domain->hash_tab[idx]);

      if (nstr == 0)
	/* Hash table entry is empty.  */
	return NULL;

      if (W (domain->must_swap, domain->orig_tab[nstr - 1].length) == len
	  && strcmp (msgid,
		     domain->data + W (domain->must_swap,
				       domain->orig_tab[nstr - 1].offset)) == 0)
	{
	  act = nstr - 1;
	  goto found;
	}

      while (1)
	{
	  if (idx >= domain->hash_size - incr)
	    idx -= domain->hash_size - incr;
	  else
	    idx += incr;

	  nstr = W (domain->must_swap, domain->hash_tab[idx]);
	  if (nstr == 0)
	    /* Hash table entry is empty.  */
	    return NULL;

	  if (W (domain->must_swap, domain->orig_tab[nstr - 1].length) == len
	      && (strcmp (msgid,
			  domain->data + W (domain->must_swap,
					    domain->orig_tab[nstr - 1].offset))
		  == 0))
	    {
	      act = nstr - 1;
	      goto found;
	    }
	}
      /* NOTREACHED */
    }
  else
    {
      /* Try the default method:  binary search in the sorted array of
	 messages.  */
      size_t top, bottom;

      bottom = 0;
      top = domain->nstrings;
      while (bottom < top)
	{
	  int cmp_val;

	  act = (bottom + top) / 2;
	  cmp_val = strcmp (msgid, (domain->data
				    + W (domain->must_swap,
					 domain->orig_tab[act].offset)));
	  if (cmp_val < 0)
	    top = act;
	  else if (cmp_val > 0)
	    bottom = act + 1;
	  else
	    goto found;
	}
      /* No translation was found.  */
      return NULL;
    }

 found:
  /* The translation was found at index ACT.  If we have to convert the
     string to use a different character set, this is the time.  */
  result = (char *) domain->data
	   + W (domain->must_swap, domain->trans_tab[act].offset);

#if defined _LIBC || HAVE_ICONV
  if (
# ifdef _LIBC
      domain->conv != (__gconv_t) -1
# else
#  if HAVE_ICONV
      domain->conv != (iconv_t) -1
#  endif
# endif
      )
    {
      /* We are supposed to do a conversion.  First allocate an
	 appropriate table with the same structure as the table
	 of translations in the file, where we can put the pointers
	 to the converted strings in.
	 The is a slight complication with the INDEX: We don't know
	 a priori which entries are plural entries. Therefore at any
	 moment we can only translate the variants 0 .. INDEX.  */

      if (domain->conv_tab == NULL
	  && ((domain->conv_tab = (char **) calloc (domain->nstrings,
						    sizeof (char *)))
	      == NULL))
	/* Mark that we didn't succeed allocating a table.  */
	domain->conv_tab = (char **) -1;

      if (__builtin_expect (domain->conv_tab == (char **) -1, 0))
	/* Nothing we can do, no more memory.  */
	goto converted;

      if (domain->conv_tab[act] == NULL
	  || *(nls_uint32 *) domain->conv_tab[act] < index)
	{
	  /* We haven't used this string so far, so it is not
	     translated yet.  Do this now.  */
	  /* We use a bit more efficient memory handling.
	     We allocate always larger blocks which get used over
	     time.  This is faster than many small allocations.   */
	  __libc_lock_define_initialized (static, lock)
	  static unsigned char *freemem;
	  static size_t freemem_size;

	  size_t resultlen;
	  const unsigned char *inbuf;
	  unsigned char *outbuf;

	  /* Note that we translate (index + 1) consecutive strings at
	     once, including the final NUL byte.  */
	  {
	    unsigned long int i = index;
	    char *p = result;
	    do
	      p += strlen (p) + 1;
	    while (i-- > 0);
	    resultlen = p - result;
	  }

	  inbuf = result;
	  outbuf = freemem + 4;

	  __libc_lock_lock (lock);

	  while (1)
	    {
# ifdef _LIBC
	      size_t non_reversible;
	      int res;

	      res = __gconv (domain->conv,
			     &inbuf, inbuf + resultlen,
			     &outbuf, outbuf + freemem_size,
			     &non_reversible);

	      if (res == __GCONV_OK || res == __GCONV_EMPTY_INPUT)
		break;

	      if (res != __GCONV_FULL_OUTPUT)
		{
		  __libc_lock_unlock (lock);
		  goto converted;
		}

	      inbuf = result;
# else
#  if HAVE_ICONV
	      const char *inptr = (const char *) inbuf;
	      size_t inleft = resultlen;
	      char *outptr = (char *) outbuf;
	      size_t outleft = freemem_size;

	      if (iconv (domain->conv, &inptr, &inleft, &outptr, &outleft)
		  != (size_t) (-1))
		{
		  outbuf = (unsigned char *) outptr;
		  break;
		}
	      if (errno != E2BIG)
		{
		  __libc_lock_unlock (lock);
		  goto converted;
		}
#  endif
# endif

	      /* We must resize the buffer.  */
	      freemem_size = 2 * freemem_size;
	      if (freemem_size < 4064)
		freemem_size = 4064;
	      freemem = (char *) malloc (freemem_size);
	      if (__builtin_expect (freemem == NULL, 0))
		{
		  __libc_lock_unlock (lock);
		  goto converted;
		}

	      outbuf = freemem + 4;
	    }

	  /* We have now in our buffer a converted string.  Put this
	     into the table of conversions.  */
	  *(nls_uint32 *) freemem = index;
	  domain->conv_tab[act] = freemem;
	  /* Shrink freemem, but keep it aligned.  */
	  freemem_size -= outbuf - freemem;
	  freemem = outbuf;
	  freemem += freemem_size & (__alignof__ (nls_uint32) - 1);
	  freemem_size = freemem_size & ~ (__alignof__ (nls_uint32) - 1);

	  __libc_lock_unlock (lock);
	}

      /* Now domain->conv_tab[act] contains the translation of at least
	 the variants 0 .. INDEX.  */
      result = domain->conv_tab[act] + 4;
    }

 converted:
  /* The result string is converted.  */

#endif /* _LIBC || HAVE_ICONV */

  /* Now skip some strings.  How much depends on the index passed in.  */
  while (index-- > 0)
    {
#ifdef _LIBC
      result = __rawmemchr (result, '\0');
#else
      result = strchr (result, '\0');
#endif
      /* And skip over the NUL byte.  */
      ++result;
    }

  return result;
}


/* Function to evaluate the plural expression and return an index value.  */
static unsigned long int
internal_function
plural_eval (struct expression *pexp, unsigned long int n)
{
  switch (pexp->operation)
    {
    case var:
      return n;
    case num:
      return pexp->val.num;
    case mult:
      return (plural_eval (pexp->val.args2.left, n)
	      * plural_eval (pexp->val.args2.right, n));
    case divide:
      return (plural_eval (pexp->val.args2.left, n)
	      / plural_eval (pexp->val.args2.right, n));
    case module:
      return (plural_eval (pexp->val.args2.left, n)
	      % plural_eval (pexp->val.args2.right, n));
    case plus:
      return (plural_eval (pexp->val.args2.left, n)
	      + plural_eval (pexp->val.args2.right, n));
    case minus:
      return (plural_eval (pexp->val.args2.left, n)
	      - plural_eval (pexp->val.args2.right, n));
    case equal:
      return (plural_eval (pexp->val.args2.left, n)
	      == plural_eval (pexp->val.args2.right, n));
    case not_equal:
      return (plural_eval (pexp->val.args2.left, n)
	      != plural_eval (pexp->val.args2.right, n));
    case land:
      return (plural_eval (pexp->val.args2.left, n)
	      && plural_eval (pexp->val.args2.right, n));
    case lor:
      return (plural_eval (pexp->val.args2.left, n)
	      || plural_eval (pexp->val.args2.right, n));
    case qmop:
      return (plural_eval (pexp->val.args3.bexp, n)
	      ? plural_eval (pexp->val.args3.tbranch, n)
	      : plural_eval (pexp->val.args3.fbranch, n));
    }
  /* NOTREACHED */
  return 0;
}


/* Return string representation of locale CATEGORY.  */
static const char *
internal_function
category_to_name (category)
     int category;
{
  const char *retval;

  switch (category)
  {
#ifdef LC_COLLATE
  case LC_COLLATE:
    retval = "LC_COLLATE";
    break;
#endif
#ifdef LC_CTYPE
  case LC_CTYPE:
    retval = "LC_CTYPE";
    break;
#endif
#ifdef LC_MONETARY
  case LC_MONETARY:
    retval = "LC_MONETARY";
    break;
#endif
#ifdef LC_NUMERIC
  case LC_NUMERIC:
    retval = "LC_NUMERIC";
    break;
#endif
#ifdef LC_TIME
  case LC_TIME:
    retval = "LC_TIME";
    break;
#endif
#ifdef LC_MESSAGES
  case LC_MESSAGES:
    retval = "LC_MESSAGES";
    break;
#endif
#ifdef LC_RESPONSE
  case LC_RESPONSE:
    retval = "LC_RESPONSE";
    break;
#endif
#ifdef LC_ALL
  case LC_ALL:
    /* This might not make sense but is perhaps better than any other
       value.  */
    retval = "LC_ALL";
    break;
#endif
  default:
    /* If you have a better idea for a default value let me know.  */
    retval = "LC_XXX";
  }

  return retval;
}

/* Guess value of current locale from value of the environment variables.  */
static const char *
internal_function
guess_category_value (category, categoryname)
     int category;
     const char *categoryname;
{
  const char *retval;

  /* The highest priority value is the `LANGUAGE' environment
     variable.  This is a GNU extension.  */
  retval = getenv ("LANGUAGE");
  if (retval != NULL && retval[0] != '\0')
    return retval;

  /* `LANGUAGE' is not set.  So we have to proceed with the POSIX
     methods of looking to `LC_ALL', `LC_xxx', and `LANG'.  On some
     systems this can be done by the `setlocale' function itself.  */
#if defined HAVE_SETLOCALE && defined HAVE_LC_MESSAGES && defined HAVE_LOCALE_NULL
  return setlocale (category, NULL);
#else
  /* Setting of LC_ALL overwrites all other.  */
  retval = getenv ("LC_ALL");
  if (retval != NULL && retval[0] != '\0')
    return retval;

  /* Next comes the name of the desired category.  */
  retval = getenv (categoryname);
  if (retval != NULL && retval[0] != '\0')
    return retval;

  /* Last possibility is the LANG environment variable.  */
  retval = getenv ("LANG");
  if (retval != NULL && retval[0] != '\0')
    return retval;

  /* We use C as the default domain.  POSIX says this is implementation
     defined.  */
  return "C";
#endif
}

/* @@ begin of epilog @@ */

/* We don't want libintl.a to depend on any other library.  So we
   avoid the non-standard function stpcpy.  In GNU C Library this
   function is available, though.  Also allow the symbol HAVE_STPCPY
   to be defined.  */
#if !_LIBC && !HAVE_STPCPY
static char *
stpcpy (dest, src)
     char *dest;
     const char *src;
{
  while ((*dest++ = *src++) != '\0')
    /* Do nothing. */ ;
  return dest - 1;
}
#endif

#if !_LIBC && !HAVE_MEMPCPY
static void *
mempcpy (dest, src, n)
     void *dest;
     const void *src;
     size_t n;
{
  return (void *) ((char *) memcpy (dest, src, n) + n);
}
#endif


#ifdef _LIBC
/* If we want to free all resources we have to do some work at
   program's end.  */
static void __attribute__ ((unused))
free_mem (void)
{
  struct binding *runp;

  for (runp = _nl_domain_bindings; runp != NULL; runp = runp->next)
    {
      if (runp->dirname != _nl_default_dirname)
	/* Yes, this is a pointer comparison.  */
	free (runp->dirname);
      if (runp->codeset != NULL)
	free (runp->codeset);
    }

  if (_nl_current_default_domain != _nl_default_default_domain)
    /* Yes, again a pointer comparison.  */
    free ((char *) _nl_current_default_domain);

  /* Remove the search tree with the known translations.  */
  __tdestroy (root, free);
}

text_set_element (__libc_subfreeres, free_mem);
#endif
