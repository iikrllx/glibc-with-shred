/* Functions to read locale data files.
Copyright (C) 1995 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "localeinfo.h"

const size_t _nl_category_num_items[] =
  {
#define DEFINE_CATEGORY(category, category_name, items, a, b, c, d) \
    [category] = _NL_NUM_##category,
#include "categories.def"
#undef	DEFINE_CATEGORY
  };

struct locale_data *
_nl_load_locale (int category, char **name)
{
  char *file;
  int fd;
  struct
    {
      unsigned int magic;
      unsigned int nstrings;
      unsigned int strindex[0];
    } *filedata;
  struct stat st;
  struct locale_data *newdata;
  int swap = 0;
  inline unsigned int SWAP (const unsigned int *inw)
    {
      const unsigned char *inc = (const unsigned char *) inw;
      if (!swap)
	return *inw;
      return (inc[3] << 24) | (inc[2] << 16) | (inc[1] << 8) | inc[0];
    }
  unsigned int i;

  if ((*name)[0] == '\0')
    {
      *name = getenv (_nl_category_names[category]);
      if (! *name || (*name) == '\0')
	*name = getenv ("LANG");
      if (! *name || (*name) == '\0')
	*name = (char *) "local";
    }

/* XXX can't use asprintf here */
  if (asprintf (&file, "%s%s/%s",
		strchr (*name, '/') != NULL ? "" : "/share/locale/", /* XXX */
		*name, _nl_category_names[category]) == -1)
    return NULL;

  fd = __open (file, O_RDONLY);
  free (file);
  if (fd < 0)
    return NULL;
  if (__fstat (fd, &st) < 0)
    goto puntfd;

  {
    /* Map in the file's data.  */
    int save = errno;
#ifndef MAP_COPY
    /* Linux seems to lack read-only copy-on-write.  */
#define MAP_COPY MAP_PRIVATE
#endif
    filedata = (void *) __mmap ((caddr_t) 0, st.st_size,
				PROT_READ, MAP_FILE|MAP_COPY, fd, 0);
    if (filedata == (void *) -1)
      {
	if (errno == ENOSYS)
	  {
	    /* No mmap; allocate a buffer and read from the file.  */
	    filedata = malloc (st.st_size);
	    if (filedata)
	      {
		off_t to_read = st.st_size;
		ssize_t nread;
		char *p = (char *) filedata;
		while (to_read > 0)
		  {
		    nread = __read (fd, p, to_read);
		    if (nread <= 0)
		      {
			free (filedata);
			if (nread == 0)
			  errno = EINVAL; /* Bizarreness going on.  */
			goto puntfd;
		      }
		    p += nread;
		    to_read -= nread;
		  }
	      }
	    else
	      goto puntfd;
	    errno = save;
	  }
	else
	  goto puntfd;
      }
  }

  if (filedata->magic == LIMAGIC (category))
    /* Good data file in our byte order.  */
    swap = 0;
  else
    {
      /* Try the other byte order.  */
      swap = 1;
      if (SWAP (&filedata->magic) != LIMAGIC (category))
	/* Bad data file in either byte order.  */
	{
	puntmap:
	  __munmap ((caddr_t) filedata, st.st_size);
	puntfd:
	  __close (fd);
	  return NULL;
	}
    }

#define W(word)	SWAP (&(word))

  if (W (filedata->nstrings) < _nl_category_num_items[category] ||
      (sizeof *filedata + W (filedata->nstrings) * sizeof (unsigned int)
       >= st.st_size))
    {
      /* Insufficient data.  */
      errno = EINVAL;
      goto puntmap;
    }

  newdata = malloc (sizeof *newdata +
		    W (filedata->nstrings) * sizeof (char *));
  if (! newdata)
    goto puntmap;

  newdata->filedata = (void *) filedata;
  newdata->filesize = st.st_size;
  newdata->nstrings = W (filedata->nstrings);
  for (i = 0; i < newdata->nstrings; ++i)
    {
      unsigned int idx = W (filedata->strindex[i]);
      if (idx >= newdata->filesize)
	{
	  free (newdata);
	  errno = EINVAL;
	  goto puntmap;
	}
      newdata->strings[i] = newdata->filedata + idx;
    }

  return newdata;
}

void
_nl_free_locale (struct locale_data *data)
{
  int save = errno;
  if (__munmap ((caddr_t) data->filedata, data->filesize) < 0)
    {
      if (errno == ENOSYS)
	free ((void *) data->filedata);
      errno = save;
    }
  free (data);
}

