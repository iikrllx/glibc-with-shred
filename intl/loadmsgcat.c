/* Load needed message catalogs.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined STDC_HEADERS || defined _LIBC
# include <stdlib.h>
#endif

#if defined HAVE_STRING_H || defined _LIBC
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE	1
# endif
# include <string.h>
#else
# include <strings.h>
#endif

#if defined HAVE_UNISTD_H || defined _LIBC
# include <unistd.h>
#endif

#ifdef _LIBC
# include <langinfo.h>
#endif

#if (defined HAVE_MMAP && defined HAVE_MUNMAP && !defined DISALLOW_MMAP) \
    || (defined _LIBC && defined _POSIX_MAPPED_FILES)
# include <sys/mman.h>
# undef HAVE_MMAP
# define HAVE_MMAP	1
#else
# undef HAVE_MMAP
#endif

#include "gettext.h"
#include "gettextP.h"

#ifdef _LIBC
# include "../locale/localeinfo.h"
#endif

/* @@ end of prolog @@ */

#ifdef _LIBC
/* Rename the non ISO C functions.  This is required by the standard
   because some ISO C functions will require linking with this object
   file and the name space must not be polluted.  */
# define open   __open
# define close  __close
# define read   __read
# define mmap   __mmap
# define munmap __munmap
#endif

/* We need a sign, whether a new catalog was loaded, which can be associated
   with all translations.  This is important if the translations are
   cached by one of GCC's features.  */
int _nl_msg_cat_cntr;

/* These structs are the constant expression for the germanic plural
   form determination.  */
static const struct expression plvar =
{
  .operation = var,
};
static const struct expression plone =
{
  .operation = num,
  .val =
  {
    .num = 1
  }
};
static struct expression germanic_plural =
{
  .operation = not_equal,
  .val =
  {
    .args2 = {
      .left = (struct expression *) &plvar,
      .right = (struct expression *) &plone
    }
  }
};


/* Load the message catalogs specified by FILENAME.  If it is no valid
   message catalog do nothing.  */
void
internal_function
_nl_load_domain (domain_file)
     struct loaded_l10nfile *domain_file;
{
  int fd;
  size_t size;
  struct stat st;
  struct mo_file_header *data = (struct mo_file_header *) -1;
  int use_mmap = 0;
  struct loaded_domain *domain;
  char *nullentry;

  domain_file->decided = 1;
  domain_file->data = NULL;

  /* If the record does not represent a valid locale the FILENAME
     might be NULL.  This can happen when according to the given
     specification the locale file name is different for XPG and CEN
     syntax.  */
  if (domain_file->filename == NULL)
    return;

  /* Try to open the addressed file.  */
  fd = open (domain_file->filename, O_RDONLY);
  if (fd == -1)
    return;

  /* We must know about the size of the file.  */
  if (fstat (fd, &st) != 0
      || (size = (size_t) st.st_size) != st.st_size
      || size < sizeof (struct mo_file_header))
    {
      /* Something went wrong.  */
      close (fd);
      return;
    }

#ifdef HAVE_MMAP
  /* Now we are ready to load the file.  If mmap() is available we try
     this first.  If not available or it failed we try to load it.  */
  data = (struct mo_file_header *) mmap (NULL, size, PROT_READ,
					 MAP_PRIVATE, fd, 0);

  if (data != (struct mo_file_header *) -1)
    {
      /* mmap() call was successful.  */
      close (fd);
      use_mmap = 1;
    }
#endif

  /* If the data is not yet available (i.e. mmap'ed) we try to load
     it manually.  */
  if (data == (struct mo_file_header *) -1)
    {
      size_t to_read;
      char *read_ptr;

      data = (struct mo_file_header *) malloc (size);
      if (data == NULL)
	return;

      to_read = size;
      read_ptr = (char *) data;
      do
	{
	  long int nb = (long int) read (fd, read_ptr, to_read);
	  if (nb == -1)
	    {
	      close (fd);
	      return;
	    }

	  read_ptr += nb;
	  to_read -= nb;
	}
      while (to_read > 0);

      close (fd);
    }

  /* Using the magic number we can test whether it really is a message
     catalog file.  */
  if (data->magic != _MAGIC && data->magic != _MAGIC_SWAPPED)
    {
      /* The magic number is wrong: not a message catalog file.  */
#ifdef HAVE_MMAP
      if (use_mmap)
	munmap ((caddr_t) data, size);
      else
#endif
	free (data);
      return;
    }

  domain_file->data
    = (struct loaded_domain *) malloc (sizeof (struct loaded_domain));
  if (domain_file->data == NULL)
    return;

  domain = (struct loaded_domain *) domain_file->data;
  domain->data = (char *) data;
  domain->use_mmap = use_mmap;
  domain->mmap_size = size;
  domain->must_swap = data->magic != _MAGIC;

  /* Fill in the information about the available tables.  */
  switch (W (domain->must_swap, data->revision))
    {
    case 0:
      domain->nstrings = W (domain->must_swap, data->nstrings);
      domain->orig_tab = (struct string_desc *)
	((char *) data + W (domain->must_swap, data->orig_tab_offset));
      domain->trans_tab = (struct string_desc *)
	((char *) data + W (domain->must_swap, data->trans_tab_offset));
      domain->hash_size = W (domain->must_swap, data->hash_tab_size);
      domain->hash_tab = (nls_uint32 *)
	((char *) data + W (domain->must_swap, data->hash_tab_offset));
      break;
    default:
      /* This is an invalid revision.  */
#ifdef HAVE_MMAP
      if (use_mmap)
	munmap ((caddr_t) data, size);
      else
#endif
	free (data);
      free (domain);
      domain_file->data = NULL;
      return;
    }

  /* Now find out about the character set the file is encoded with.
     This can be found (in textual form) in the entry "".  If this
     entry does not exist or if this does not contain the `charset='
     information, we will assume the charset matches the one the
     current locale and we don't have to perform any conversion.  */
#ifdef _LIBC
  domain->conv = (__gconv_t) -1;
#else
# if HAVE_ICONV
  domain->conv = (iconv_t) -1;
# endif
#endif
  nullentry = _nl_find_msg (domain_file, "", 0);
  if (nullentry != NULL)
    {
      const char *charsetstr = strstr (nullentry, "charset=");
      const char *plural;
      const char *nplurals;

      if (charsetstr != NULL)
	{
	  size_t len;
	  char *charset;
	  const char *outcharset;

	  charsetstr += strlen ("charset=");
	  len = strcspn (charsetstr, " \t\n");

	  charset = (char *) alloca (len + 1);
#if defined _LIBC || HAVE_MEMPCPY
	  *((char *) mempcpy (charset, charsetstr, len)) = '\0';
#else
	  memcpy (charset, charsetstr, len);
	  charset[len] = '\0';
#endif

	  /* The output charset should normally be determined by the
	     locale.  But sometimes the locale is not used or not correctly
	     set up so we provide a possibility to override this.  */
	  outcharset = getenv ("OUTPUT_CHARSET");
	  if (outcharset == NULL || outcharset[0] == '\0')
	    outcharset = (*_nl_current[LC_CTYPE])->values[_NL_ITEM_INDEX (CODESET)].string;

#ifdef _LIBC
	  if (__gconv_open (outcharset, charset, &domain->conv,
			    GCONV_AVOID_NOCONV)
	      != __GCONV_OK)
	    domain->conv = (__gconv_t) -1;
#else
# if HAVE_ICONV
	  domain->conv = iconv_open (outcharset, charset);
# endif
#endif
	}

      /* Also look for a plural specification.  */
      plural = strstr (nullentry, "plural=");
      nplurals = strstr (nullentry, "nplurals=");
      if (plural == NULL || nplurals == NULL)
	{
	  /* By default we are using the Germanic form: singular form only
	     for `one', the plural form otherwise.  Yes, this is also what
	     English is using since English is a Germanic language.  */
	no_plural:
	  domain->plural = &germanic_plural;
	  domain->nplurals = 2;
	}
      else
	{
	  /* First get the number.  */
	  char *endp;
	  struct parse_args args;

	  nplurals += 9;
	  while (*nplurals != '\0' && isspace (*nplurals))
	    ++nplurals;
	  domain->nplurals = strtoul (nplurals, &endp, 10);
	  if (nplurals == endp)
	    goto no_plural;

	  /* Due to the restrictions bison imposes onto the interface of the
	     scanner function we have to put the input string and the result
	     passed up from the parser into the same structure which address
	     is passed down to the parser.  */
	  plural += 7;
	  args.cp = plural;
	  if (__gettextparse (&args) != 0)
	    goto no_plural;
	  domain->plural = args.res;
	}
    }
}


#ifdef _LIBC
void
internal_function
_nl_unload_domain (domain)
     struct loaded_domain *domain;
{
  if (domain->plural != &germanic_plural)
    __gettext_free_exp (domain->plural);

#ifdef _LIBC
  if (domain->conv != (__gconv_t) -1)
    __gconv_close (domain->conv);
#else
# if HAVE_ICONV
  if (domain->conv != (iconv_t) -1)
    iconv_close (domain->conv);
# endif
#endif

#ifdef _POSIX_MAPPED_FILES
  if (domain->use_mmap)
    munmap ((caddr_t) domain->data, domain->mmap_size);
  else
#endif	/* _POSIX_MAPPED_FILES */
    free ((void *) domain->data);

  free (domain);
}
#endif
