/* Map in a shared object's segments from the file.
   Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
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

#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "dynamic-link.h"


/* On some systems, no flag bits are given to specify file mapping.  */
#ifndef MAP_FILE
#define MAP_FILE	0
#endif

/* The right way to map in the shared library files is MAP_COPY, which
   makes a virtual copy of the data at the time of the mmap call; this
   guarantees the mapped pages will be consistent even if the file is
   overwritten.  Some losing VM systems like Linux's lack MAP_COPY.  All we
   get is MAP_PRIVATE, which copies each page when it is modified; this
   means if the file is overwritten, we may at some point get some pages
   from the new version after starting with pages from the old version.  */
#ifndef MAP_COPY
#define MAP_COPY	MAP_PRIVATE
#endif

/* Some systems link their relocatable objects for another base address
   than 0.  We want to know the base address for these such that we can
   subtract this address from the segment addresses during mapping.
   This results in a more efficient address space usage.  Defaults to
   zero for almost all systems.  */
#ifndef MAP_BASE_ADDR
#define MAP_BASE_ADDR(l)	0
#endif


#include <endian.h>
#if BYTE_ORDER == BIG_ENDIAN
#define byteorder ELFDATA2MSB
#define byteorder_name "big-endian"
#elif BYTE_ORDER == LITTLE_ENDIAN
#define byteorder ELFDATA2LSB
#define byteorder_name "little-endian"
#else
#error "Unknown BYTE_ORDER " BYTE_ORDER
#define byteorder ELFDATANONE
#endif

#define STRING(x) #x

#ifdef MAP_ANON
/* The fd is not examined when using MAP_ANON.  */
#define ANONFD -1
#else
int _dl_zerofd = -1;
#define ANONFD _dl_zerofd
#endif

/* Handle situations where we have a preferred location in memory for
   the shared objects.  */
#ifdef ELF_PREFERRED_ADDRESS_DATA
ELF_PREFERRED_ADDRESS_DATA;
#endif
#ifndef ELF_PREFERRED_ADDRESS
#define ELF_PREFERRED_ADDRESS(loader, maplength, mapstartpref) (mapstartpref)
#endif
#ifndef ELF_FIXED_ADDRESS
#define ELF_FIXED_ADDRESS(loader, mapstart) ((void) 0)
#endif

size_t _dl_pagesize;

extern const char *_dl_platform;
extern size_t _dl_platformlen;

/* Local version of `strdup' function.  */
static inline char *
local_strdup (const char *s)
{
  size_t len = strlen (s) + 1;
  void *new = malloc (len);

  if (new == NULL)
    return NULL;

  return (char *) memcpy (new, s, len);
}


/* Implement cache for search path lookup.  */
#if 0
/* This is how generated should look like.  I'll remove this once I'm
   sure everything works correctly.  */
static struct r_search_path_elem rtld_search_dir1 =
  { "/lib/", 5, unknown, 0, unknown, NULL };
static struct r_search_path_elem rtld_search_dir2 =
  { "/usr/lib/", 9, unknown, 0, unknown, &r ld_search_dir1 };

static struct r_search_path_elem *rtld_search_dirs[] =
{
  &rtld_search_dir1,
  &rtld_search_dir2,
  NULL
};

static struct r_search_path_elem *all_dirs = &rtld_search_dir2;
#else
# include "rtldtbl.h"
#endif

static size_t max_dirnamelen;

static inline struct r_search_path_elem **
fillin_rpath (char *rpath, struct r_search_path_elem **result, const char *sep,
	      const char **trusted)
{
  char *cp;
  size_t nelems = 0;

  while ((cp = __strsep (&rpath, sep)) != NULL)
    {
      struct r_search_path_elem *dirp;
      size_t len = strlen (cp);
      /* Remove trailing slashes.  */
      while (len > 1 && cp[len - 1] == '/')
	--len;

      /* Make sure we don't use untrusted directories if we run SUID.  */
      if (trusted != NULL)
	{
	  const char **trun = trusted;

	  /* All trusted directory must be complete name.  */
	  if (cp[0] != '/')
	    continue;

	  while (*trun != NULL
		 && (memcmp (*trun, cp, len) != 0 || (*trun)[len] != '\0'))
	    ++trun;

	  if (*trun == NULL)
	    /* It's no trusted directory, skip it.  */
	    continue;
	}

      /* Now add one.  */
      if (len > 0)
	cp[len++] = '/';

      /* See if this directory is already known.  */
      for (dirp = all_dirs; dirp != NULL; dirp = dirp->next)
	if (dirp->dirnamelen == len && strcmp (cp, dirp->dirname) == 0)
	  break;

      if (dirp != NULL)
	{
	  /* It is available, see whether it's in our own list.  */
	  size_t cnt;
	  for (cnt = 0; cnt < nelems; ++cnt)
	    if (result[cnt] == dirp)
	      break;

	  if (cnt == nelems)
	    result[nelems++] = dirp;
	}
      else
	{
	  /* It's a new directory.  Create an entry and add it.  */
	  dirp = (struct r_search_path_elem *) malloc (sizeof (*dirp));
	  if (dirp == NULL)
	    _dl_signal_error (ENOMEM, NULL,
			      "cannot create cache for search path");

	  dirp->dirnamelen = len;
	  /* We have to make sure all the relative directories are never
	     ignored.  The current directory might change and all our
	     saved information would be void.  */
	  dirp->dirstatus = cp[0] != '/' ? existing : unknown;

	  /* Add the name of the machine dependent directory if a machine
	     is defined.  */
	  if (_dl_platform != NULL)
	    {
	      char *tmp;

	      dirp->machdirnamelen = len + _dl_platformlen + 1;
	      tmp = (char *) malloc (len + _dl_platformlen + 2);
	      if (tmp == NULL)
		_dl_signal_error (ENOMEM, NULL,
				  "cannot create cache for search path");
	      memcpy (tmp, cp, len);
	      memcpy (tmp + len, _dl_platform, _dl_platformlen);
	      tmp[len + _dl_platformlen] = '/';
	      tmp[len + _dl_platformlen + 1] = '\0';

	      dirp->dirname = tmp;
	      dirp->machdirstatus = dirp->dirstatus;

	      if (max_dirnamelen < dirp->machdirnamelen)
		max_dirnamelen = dirp->machdirnamelen;
	    }
	  else
	    {
	      char *tmp;

	      dirp->machdirnamelen = len;
	      dirp->machdirstatus = nonexisting;

	      tmp = (char *) malloc (len + 1);
	      if (tmp == NULL)
		_dl_signal_error (ENOMEM, NULL,
				  "cannot create cache for search path");
	      memcpy (tmp, cp, len);
	      tmp[len] = '\0';

	      if (max_dirnamelen < dirp->dirnamelen)
		max_dirnamelen = dirp->dirnamelen;

	      dirp->dirname = tmp;
	    }

	  dirp->next = all_dirs;
	  all_dirs = dirp;

	  /* Put it in the result array.  */
	  result[nelems++] = dirp;
	}
    }

  /* Terminate the array.  */
  result[nelems] = NULL;

  return result;
}


static struct r_search_path_elem **
decompose_rpath (const char *rpath, size_t additional_room)
{
  /* Make a copy we can work with.  */
  char *copy = strdupa (rpath);
  char *cp;
  struct r_search_path_elem **result;
  /* First count the number of necessary elements in the result array.  */
  size_t nelems = 0;

  for (cp = copy; *cp != '\0'; ++cp)
    if (*cp == ':')
      ++nelems;

  /* Allocate room for the result.  NELEMS + 1 + ADDITIONAL_ROOM is an upper
     limit for the number of necessary entries.  */
  result = (struct r_search_path_elem **) malloc ((nelems + 1
						   + additional_room + 1)
						  * sizeof (*result));
  if (result == NULL)
    _dl_signal_error (ENOMEM, NULL, "cannot create cache for search path");

  return fillin_rpath (copy, result, ":", NULL);
}


void
_dl_init_paths (void)
{
  struct r_search_path_elem **pelem;

  /* We have in `search_path' the information about the RPATH of the
     dynamic loader.  Now fill in the information about the applications
     RPATH and the directories addressed by the LD_LIBRARY_PATH environment
     variable.  */
  struct link_map *l;

  /* First determine how many elements the LD_LIBRARY_PATH contents has.  */
  const char *llp = getenv ("LD_LIBRARY_PATH");
  size_t nllp;

  if (llp != NULL && *llp != '\0')
    {
      /* Simply count the number of colons.  */
      const char *cp = llp;
      nllp = 1;
      while (*cp)
	if (*cp++ == ':')
	  ++nllp;
    }
  else
    nllp = 0;

  l = _dl_loaded;
  if (l && l->l_type != lt_loaded && l->l_info[DT_RPATH])
    {
      /* Allocate room for the search path and fill in information from
	 RPATH.  */
      l->l_rpath_dirs =
	decompose_rpath ((const char *) (l->l_addr
					 + l->l_info[DT_STRTAB]->d_un.d_ptr
					 + l->l_info[DT_RPATH]->d_un.d_val),
			 nllp);
    }
  else
    {
      /* If we have no LD_LIBRARY_PATH and no RPATH we must tell this
	 somehow to prevent we look this up again and again.  */
      if (nllp == 0)
	 l->l_rpath_dirs = (struct r_search_path_elem **) -1l;
      else
	{
	  l->l_rpath_dirs =
	    (struct r_search_path_elem **) malloc ((nllp + 1)
						   * sizeof (*l->l_rpath_dirs));
	  if (l->l_rpath_dirs == NULL)
	    _dl_signal_error (ENOMEM, NULL,
			      "cannot create cache for search path");
	  l->l_rpath_dirs[0] = NULL;
	}
    }

  if (nllp > 0)
    {
      static const char *trusted_dirs[] =
      {
#include "trusted-dirs.h"
	NULL
      };
      char *copy = strdupa (llp);

      /* Decompose the LD_LIBRARY_PATH and fill in the result.
         First search for the next place to enter elements.  */
      struct r_search_path_elem **result = l->l_rpath_dirs;
      while (*result != NULL)
	++result;

      /* We need to take care that the LD_LIBRARY_PATH environement
	 variable can contain a semicolon.  */
      (void) fillin_rpath (copy, result, ":;",
			   __libc_enable_secure ? trusted_dirs : NULL);
    }

  /* Now set up the rest of the rtld_search_dirs.  */
  for (pelem = rtld_search_dirs; *pelem != NULL; ++pelem)
    {
      struct r_search_path_elem *relem = *pelem;

      if (_dl_platform != NULL)
	{
	  char *tmp;

	  relem->machdirnamelen = relem->dirnamelen + _dl_platformlen + 1;
	  tmp = (char *) malloc (relem->machdirnamelen + 1);
	  if (tmp == NULL)
	    _dl_signal_error (ENOMEM, NULL,
			      "cannot create cache for search path");

	  memcpy (tmp, relem->dirname, relem->dirnamelen);
	  memcpy (tmp + relem->dirnamelen, _dl_platform, _dl_platformlen);
	  tmp[relem->dirnamelen + _dl_platformlen] = '/';
	  tmp[relem->dirnamelen + _dl_platformlen + 1] = '\0';

	  relem->dirname = tmp;

	  relem->machdirstatus = unknown;

	  if (max_dirnamelen < relem->machdirnamelen)
	    max_dirnamelen = relem->machdirnamelen;
	}
      else
	{
	  relem->machdirnamelen = relem->dirnamelen;
	  relem->machdirstatus = nonexisting;

	  if (max_dirnamelen < relem->dirnamelen)
	    max_dirnamelen = relem->dirnamelen;
	}
    }
}


/* Map in the shared object NAME, actually located in REALNAME, and already
   opened on FD.  */

struct link_map *
_dl_map_object_from_fd (char *name, int fd, char *realname,
			struct link_map *loader, int l_type)
{
  struct link_map *l = NULL;
  void *file_mapping = NULL;
  size_t mapping_size = 0;

#define LOSE(s) lose (0, (s))
  void lose (int code, const char *msg)
    {
      (void) __close (fd);
      if (file_mapping)
	__munmap (file_mapping, mapping_size);
      if (l)
	{
	  /* Remove the stillborn object from the list and free it.  */
	  if (l->l_prev)
	    l->l_prev->l_next = l->l_next;
	  if (l->l_next)
	    l->l_next->l_prev = l->l_prev;
	  free (l);
	}
      free (name);	/* XXX Can this be correct? --drepper */
      free (realname);
      _dl_signal_error (code, name, msg);
    }

  inline caddr_t map_segment (ElfW(Addr) mapstart, size_t len,
			      int prot, int fixed, off_t offset)
    {
      caddr_t mapat = __mmap ((caddr_t) mapstart, len, prot,
			      fixed|MAP_COPY|MAP_FILE,
			      fd, offset);
      if (mapat == (caddr_t) -1)
	lose (errno, "failed to map segment from shared object");
      return mapat;
    }

  /* Make sure LOCATION is mapped in.  */
  void *map (off_t location, size_t size)
    {
      if ((off_t) mapping_size <= location + (off_t) size)
	{
	  void *result;
	  if (file_mapping)
	    __munmap (file_mapping, mapping_size);
	  mapping_size = (location + size + 1 + _dl_pagesize - 1);
	  mapping_size &= ~(_dl_pagesize - 1);
	  result = __mmap (file_mapping, mapping_size, PROT_READ,
			   MAP_COPY|MAP_FILE, fd, 0);
	  if (result == (void *) -1)
	    lose (errno, "cannot map file data");
	  file_mapping = result;
	}
      return file_mapping + location;
    }

  const ElfW(Ehdr) *header;
  const ElfW(Phdr) *phdr;
  const ElfW(Phdr) *ph;
  int type;

  /* Look again to see if the real name matched another already loaded.  */
  for (l = _dl_loaded; l; l = l->l_next)
    if (! strcmp (realname, l->l_name))
      {
	struct libname_list *lnp, *lastp;
	/* The object is already loaded.
	   Just bump its reference count and return it.  */
	__close (fd);

	/* If the name is not in the list of names for this object add
	   it.  */
	free (realname);
	lastp = NULL;
	for (lnp = l->l_libname; lnp != NULL; lastp = lnp, lnp = lnp->next)
	  if (strcmp (name, lnp->name) == 0)
	    {
	      free (name);
	      break;
	    }
	if (lnp == NULL)
	  {
	    struct libname_list *newname = malloc (sizeof *newname);
	    if (newname == NULL)
	      /* No more memory.  */
	      lose (ENOMEM, "cannot allocate name record");
	    /* The object should have a libname set.  */
	    assert (lastp != NULL);

	    newname->name = name;
	    newname->next = NULL;
	    lastp->next = newname;
	  }
	++l->l_opencount;
	return l;
      }

  /* Map in the first page to read the header.  */
  header = map (0, sizeof *header);

  /* Check the header for basic validity.  */
  if (*(Elf32_Word *) &header->e_ident !=
#if BYTE_ORDER == LITTLE_ENDIAN
      ((ELFMAG0 << (EI_MAG0 * 8)) |
       (ELFMAG1 << (EI_MAG1 * 8)) |
       (ELFMAG2 << (EI_MAG2 * 8)) |
       (ELFMAG3 << (EI_MAG3 * 8)))
#else
      ((ELFMAG0 << (EI_MAG3 * 8)) |
       (ELFMAG1 << (EI_MAG2 * 8)) |
       (ELFMAG2 << (EI_MAG1 * 8)) |
       (ELFMAG3 << (EI_MAG0 * 8)))
#endif
      )
    LOSE ("invalid ELF header");
#define ELF32_CLASS ELFCLASS32
#define ELF64_CLASS ELFCLASS64
  if (header->e_ident[EI_CLASS] != ELFW(CLASS))
    LOSE ("ELF file class not " STRING(__ELF_WORDSIZE) "-bit");
  if (header->e_ident[EI_DATA] != byteorder)
    LOSE ("ELF file data encoding not " byteorder_name);
  if (header->e_ident[EI_VERSION] != EV_CURRENT)
    LOSE ("ELF file version ident not " STRING(EV_CURRENT));
  if (header->e_version != EV_CURRENT)
    LOSE ("ELF file version not " STRING(EV_CURRENT));
  if (! elf_machine_matches_host (header->e_machine))
    LOSE ("ELF file machine architecture not " ELF_MACHINE_NAME);
  if (header->e_phentsize != sizeof (ElfW(Phdr)))
    LOSE ("ELF file's phentsize not the expected size");

#ifndef MAP_ANON
#define MAP_ANON 0
  if (_dl_zerofd == -1)
    {
      _dl_zerofd = _dl_sysdep_open_zero_fill ();
      if (_dl_zerofd == -1)
	{
	  __close (fd);
	  _dl_signal_error (errno, NULL, "cannot open zero fill device");
	}
    }
#endif

  /* Enter the new object in the list of loaded objects.  */
  l = _dl_new_object (realname, name, l_type);
  if (! l)
    lose (ENOMEM, "cannot create shared object descriptor");
  l->l_opencount = 1;
  l->l_loader = loader;

  /* Extract the remaining details we need from the ELF header
     and then map in the program header table.  */
  l->l_entry = header->e_entry;
  type = header->e_type;
  l->l_phnum = header->e_phnum;
  phdr = map (header->e_phoff, l->l_phnum * sizeof (ElfW(Phdr)));

  {
    /* Scan the program header table, collecting its load commands.  */
    struct loadcmd
      {
	ElfW(Addr) mapstart, mapend, dataend, allocend;
	off_t mapoff;
	int prot;
      } loadcmds[l->l_phnum], *c;
    size_t nloadcmds = 0;

    l->l_ld = 0;
    l->l_phdr = 0;
    l->l_addr = 0;
    for (ph = phdr; ph < &phdr[l->l_phnum]; ++ph)
      switch (ph->p_type)
	{
	  /* These entries tell us where to find things once the file's
	     segments are mapped in.  We record the addresses it says
	     verbatim, and later correct for the run-time load address.  */
	case PT_DYNAMIC:
	  l->l_ld = (void *) ph->p_vaddr;
	  break;
	case PT_PHDR:
	  l->l_phdr = (void *) ph->p_vaddr;
	  break;

	case PT_LOAD:
	  /* A load command tells us to map in part of the file.
	     We record the load commands and process them all later.  */
	  if (ph->p_align % _dl_pagesize != 0)
	    LOSE ("ELF load command alignment not page-aligned");
	  if ((ph->p_vaddr - ph->p_offset) % ph->p_align)
	    LOSE ("ELF load command address/offset not properly aligned");
	  {
	    struct loadcmd *c = &loadcmds[nloadcmds++];
	    c->mapstart = ph->p_vaddr & ~(ph->p_align - 1);
	    c->mapend = ((ph->p_vaddr + ph->p_filesz + _dl_pagesize - 1)
			 & ~(_dl_pagesize - 1));
	    c->dataend = ph->p_vaddr + ph->p_filesz;
	    c->allocend = ph->p_vaddr + ph->p_memsz;
	    c->mapoff = ph->p_offset & ~(ph->p_align - 1);
	    c->prot = 0;
	    if (ph->p_flags & PF_R)
	      c->prot |= PROT_READ;
	    if (ph->p_flags & PF_W)
	      c->prot |= PROT_WRITE;
	    if (ph->p_flags & PF_X)
	      c->prot |= PROT_EXEC;
	    break;
	  }
	}

    /* We are done reading the file's headers now.  Unmap them.  */
    __munmap (file_mapping, mapping_size);

    /* Now process the load commands and map segments into memory.  */
    c = loadcmds;

    if (type == ET_DYN || type == ET_REL)
      {
	/* This is a position-independent shared object.  We can let the
	   kernel map it anywhere it likes, but we must have space for all
	   the segments in their specified positions relative to the first.
	   So we map the first segment without MAP_FIXED, but with its
	   extent increased to cover all the segments.  Then we remove
	   access from excess portion, and there is known sufficient space
	   there to remap from the later segments.

	   As a refinement, sometimes we have an address that we would
	   prefer to map such objects at; but this is only a preference,
	   the OS can do whatever it likes. */
 	caddr_t mapat;
	ElfW(Addr) mappref;
	size_t maplength = loadcmds[nloadcmds - 1].allocend - c->mapstart;
	mappref = (ELF_PREFERRED_ADDRESS (loader, maplength, c->mapstart)
		   - MAP_BASE_ADDR (l));
	mapat = map_segment (mappref, maplength, c->prot, 0, c->mapoff);
	l->l_addr = (ElfW(Addr)) mapat - c->mapstart;

	/* Change protection on the excess portion to disallow all access;
	   the portions we do not remap later will be inaccessible as if
	   unallocated.  Then jump into the normal segment-mapping loop to
	   handle the portion of the segment past the end of the file
	   mapping.  */
	__mprotect ((caddr_t) (l->l_addr + c->mapend),
		    loadcmds[nloadcmds - 1].allocend - c->mapend,
		    0);
	goto postmap;
      }
    else
      {
	/* Notify ELF_PREFERRED_ADDRESS that we have to load this one
	   fixed.  */
	ELF_FIXED_ADDRESS (loader, c->mapstart);
      }

    while (c < &loadcmds[nloadcmds])
      {
	if (c->mapend > c->mapstart)
	  /* Map the segment contents from the file.  */
	  map_segment (l->l_addr + c->mapstart, c->mapend - c->mapstart,
		       c->prot, MAP_FIXED, c->mapoff);

      postmap:
	if (c->allocend > c->dataend)
	  {
	    /* Extra zero pages should appear at the end of this segment,
	       after the data mapped from the file.   */
	    ElfW(Addr) zero, zeroend, zeropage;

	    zero = l->l_addr + c->dataend;
	    zeroend = l->l_addr + c->allocend;
	    zeropage = (zero + _dl_pagesize - 1) & ~(_dl_pagesize - 1);

	    if (zeroend < zeropage)
	      /* All the extra data is in the last page of the segment.
		 We can just zero it.  */
	      zeropage = zeroend;

	    if (zeropage > zero)
	      {
		/* Zero the final part of the last page of the segment.  */
		if ((c->prot & PROT_WRITE) == 0)
		  {
		    /* Dag nab it.  */
		    if (__mprotect ((caddr_t) (zero & ~(_dl_pagesize - 1)),
				    _dl_pagesize, c->prot|PROT_WRITE) < 0)
		      lose (errno, "cannot change memory protections");
		  }
		memset ((void *) zero, 0, zeropage - zero);
		if ((c->prot & PROT_WRITE) == 0)
		  __mprotect ((caddr_t) (zero & ~(_dl_pagesize - 1)),
			      _dl_pagesize, c->prot);
	      }

	    if (zeroend > zeropage)
	      {
		/* Map the remaining zero pages in from the zero fill FD.  */
		caddr_t mapat;
		mapat = __mmap ((caddr_t) zeropage, zeroend - zeropage,
				c->prot, MAP_ANON|MAP_PRIVATE|MAP_FIXED,
				ANONFD, 0);
		if (mapat == (caddr_t) -1)
		  lose (errno, "cannot map zero-fill pages");
	      }
	  }

	++c;
      }

    if (l->l_phdr == 0)
      {
	/* There was no PT_PHDR specified.  We need to find the phdr in the
           load image ourselves.  We assume it is in fact in the load image
           somewhere, and that the first load command starts at the
           beginning of the file and thus contains the ELF file header.  */
	ElfW(Addr) bof = l->l_addr + loadcmds[0].mapstart;
	assert (loadcmds[0].mapoff == 0);
	l->l_phdr = (void *) (bof + ((const ElfW(Ehdr) *) bof)->e_phoff);
      }
    else
      /* Adjust the PT_PHDR value by the runtime load address.  */
      (ElfW(Addr)) l->l_phdr += l->l_addr;
  }

  /* We are done mapping in the file.  We no longer need the descriptor.  */
  __close (fd);

  if (l->l_type == lt_library && type == ET_EXEC)
    l->l_type = lt_executable;

  if (l->l_ld == 0)
    {
      if (type == ET_DYN)
	LOSE ("object file has no dynamic section");
    }
  else
    (ElfW(Addr)) l->l_ld += l->l_addr;

  l->l_entry += l->l_addr;

  elf_get_dynamic_info (l->l_ld, l->l_info);
  if (l->l_info[DT_HASH])
    _dl_setup_hash (l);

  return l;
}

/* Try to open NAME in one of the directories in DIRS.
   Return the fd, or -1.  If successful, fill in *REALNAME
   with the malloc'd full directory name.  */

static int
open_path (const char *name, size_t namelen,
	   struct r_search_path_elem **dirs,
	   char **realname)
{
  char *buf;
  int fd = -1;

  if (dirs == NULL || *dirs == NULL)
    {
      __set_errno (ENOENT);
      return -1;
    }

  buf = __alloca (max_dirnamelen + namelen);
  do
    {
      struct r_search_path_elem *this_dir = *dirs;
      size_t buflen = 0;

      if (this_dir->machdirstatus != nonexisting)
	{
	  /* Construct the pathname to try.  */
	  (void) memcpy (buf, this_dir->dirname, this_dir->machdirnamelen);
	  (void) memcpy (buf + this_dir->machdirnamelen, name, namelen);
	  buflen = this_dir->machdirnamelen + namelen;

	  fd = __open (buf, O_RDONLY);
	  if (this_dir->machdirstatus == unknown)
	    if (fd != -1)
	      this_dir->machdirstatus = existing;
	    else
	      {
		/* We failed to open machine dependent library.  Let's
		   test whether there is any directory at all.  */
		struct stat st;

		buf[this_dir->machdirnamelen - 1] = '\0';

		if (stat (buf, &st) != 0 || ! S_ISDIR (st.st_mode))
		  /* The directory does not exist ot it is no directory.  */
		  this_dir->machdirstatus = nonexisting;
		else
		  this_dir->machdirstatus = existing;
	      }
	}

      if (fd == -1 && this_dir->dirstatus != nonexisting)
	{
	  /* Construct the pathname to try.  */
	  (void) memcpy (buf, this_dir->dirname, this_dir->dirnamelen);
	  (void) memcpy (buf + this_dir->dirnamelen, name, namelen);
	  buflen = this_dir->dirnamelen + namelen;

	  fd = __open (buf, O_RDONLY);
	  if (this_dir->dirstatus == unknown)
	    if (fd != -1)
	      this_dir->dirstatus = existing;
	    else
	      /* We failed to open library.  Let's test whether there
		 is any directory at all.  */
	      if (this_dir->dirnamelen <= 1)
		this_dir->dirstatus = existing;
	      else
		{
		  struct stat st;

		  buf[this_dir->dirnamelen - 1] = '\0';

		  if (stat (buf, &st) != 0 || ! S_ISDIR (st.st_mode))
		    /* The directory does not exist ot it is no directory.  */
		    this_dir->dirstatus = nonexisting;
		  else
		    this_dir->dirstatus = existing;
		}
	}

      if (fd != -1)
	{
	  *realname = malloc (buflen);
	  if (*realname)
	    {
	      memcpy (*realname, buf, buflen);
	      return fd;
	    }
	  else
	    {
	      /* No memory for the name, we certainly won't be able
		 to load and link it.  */
	      __close (fd);
	      return -1;
	    }
	}
      if (errno != ENOENT && errno != EACCES)
	/* The file exists and is readable, but something went wrong.  */
	return -1;
    }
  while (*++dirs != NULL);

  return -1;
}

/* Map in the shared object file NAME.  */

struct link_map *
_dl_map_object (struct link_map *loader, const char *name, int type,
		int trace_mode)
{
  int fd;
  char *realname;
  char *name_copy;
  struct link_map *l;

  /* Look for this name among those already loaded.  */
  for (l = _dl_loaded; l; l = l->l_next)
    if (_dl_name_match_p (name, l) ||
	/* If the requested name matches the soname of a loaded object,
	   use that object.  */
	(l->l_info[DT_SONAME] &&
	 ! strcmp (name, (const char *) (l->l_addr +
					 l->l_info[DT_STRTAB]->d_un.d_ptr +
					 l->l_info[DT_SONAME]->d_un.d_val))))
      {
	/* The object is already loaded.
	   Just bump its reference count and return it.  */
	++l->l_opencount;
	return l;
      }

  if (strchr (name, '/') == NULL)
    {
      /* Search for NAME in several places.  */

      size_t namelen = strlen (name) + 1;

      fd = -1;

      /* First try the DT_RPATH of the dependent object that caused NAME
	 to be loaded.  Then that object's dependent, and on up.  */
      for (l = loader; fd == -1 && l; l = l->l_loader)
	if (l && l->l_info[DT_RPATH])
	  {
	    /* Make sure the cache information is available.  */
	    if (l->l_rpath_dirs == NULL)
	      {
		size_t ptrval = (l->l_addr
				 + l->l_info[DT_STRTAB]->d_un.d_ptr
				 + l->l_info[DT_RPATH]->d_un.d_val);
		l->l_rpath_dirs =
		  decompose_rpath ((const char *) ptrval, 0);
	      }

	    if (l->l_rpath_dirs != (struct r_search_path_elem **) -1l)
	      fd = open_path (name, namelen, l->l_rpath_dirs, &realname);
	  }

      /* If dynamically linked, try the DT_RPATH of the executable itself
	 and the LD_LIBRARY_PATH environment variable.  */
      l = _dl_loaded;
      if (fd == -1 && l && l->l_type != lt_loaded
	  && l->l_rpath_dirs != (struct r_search_path_elem **) -1l)
	fd = open_path (name, namelen, l->l_rpath_dirs, &realname);

      if (fd == -1)
	{
	  /* Check the list of libraries in the file /etc/ld.so.cache,
	     for compatibility with Linux's ldconfig program.  */
	  extern const char *_dl_load_cache_lookup (const char *name);
	  const char *cached = _dl_load_cache_lookup (name);
	  if (cached)
	    {
	      fd = __open (cached, O_RDONLY);
	      if (fd != -1)
		{
		  realname = local_strdup (cached);
		  if (realname == NULL)
		    {
		      __close (fd);
		      fd = -1;
		    }
		}
	    }
	}

      /* Finally, try the default path.  */
      if (fd == -1)
	fd = open_path (name, namelen, rtld_search_dirs, &realname);
    }
  else
    {
      fd = __open (name, O_RDONLY);
      if (fd != -1)
	{
	  realname = local_strdup (name);
	  if (realname == NULL)
	    {
	      __close (fd);
	      fd = -1;
	    }
	}
    }

  if (fd != -1)
    {
      name_copy = local_strdup (name);
      if (name_copy == NULL)
	{
	  __close (fd);
	  fd = -1;
	}
    }

  if (fd == -1)
    {
      if (trace_mode)
	{
	  /* We haven't found an appropriate library.  But since we
	     are only interested in the list of libraries this isn't
	     so severe.  Fake an entry with all the information we
	     have.  */
	  static const ElfW(Symndx) dummy_bucket = STN_UNDEF;

	  /* Enter the new object in the list of loaded objects.  */
	  if ((name_copy = local_strdup (name)) == NULL
	      || (l = _dl_new_object (name_copy, name, type)) == NULL)
	    _dl_signal_error (ENOMEM, name,
			      "cannot create shared object descriptor");
	  /* We use an opencount of 0 as a sign for the faked entry.  */
	  l->l_opencount = 0;
	  l->l_reserved = 0;
	  l->l_buckets = &dummy_bucket;
	  l->l_nbuckets = 1;
	  l->l_relocated = 1;

	  return l;
	}
      else
	_dl_signal_error (errno, name, "cannot open shared object file");
    }

  return _dl_map_object_from_fd (name_copy, fd, realname, loader, type);
}
