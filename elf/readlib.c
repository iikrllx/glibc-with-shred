/* Copyright (C) 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Jaeger <aj@suse.de>, 1999 and
		  Jakub Jelinek <jakub@redhat.com>, 1999.

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

/* The code in this file and in readelflib is a heavily simplified
   version of the readelf program that's part of the current binutils
   development version.  Besides the simplification, it has also been
   modified to read some other file formats.  */


#include <elf.h>
#include <error.h>
#include <link.h>
#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <a.out.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <gnu/lib-names.h>

#include "ldconfig.h"

#define Elf32_CLASS ELFCLASS32
#define Elf64_CLASS ELFCLASS64

struct known_names
{
  const char *soname;
  int flag;
};

static struct known_names interpreters [] =
{
  {"/lib/" LD_SO, FLAG_ELF_LIBC6},
  {"/lib/ld-linux.so.1", FLAG_ELF_LIBC5}
};

static struct known_names known_libs [] =
{
  /* Old names:  */
  {"libc.so.5", FLAG_ELF_LIBC5},
  {"libm.so.5", FLAG_ELF_LIBC5},
  /* Current names:  */
  {LIBC_SO, FLAG_ELF_LIBC6},
  {LIBM_SO, FLAG_ELF_LIBC6}
};



/* Returns 0 if everything is ok, != 0 in case of error.  */
int
process_file (const char *file_name, const char *lib, int *flag,
	      char **soname, int is_link)
{
  FILE *file;
  struct stat statbuf;
  void *file_contents;
  int ret;

  ElfW(Ehdr) *elf_header;
  struct exec *aout_header;

  ret = 0;
  *flag = FLAG_ANY;
  *soname = NULL;

  file = fopen (file_name, "rb");
  if (file == NULL)
    {
      /* No error for stale symlink.  */
      if (is_link && strstr (file_name, ".so.") != NULL)
	return 1;
      error (0, 0, _("Input file %s not found.\n"), file_name);
      return 1;
    }

  if (fstat (fileno (file), &statbuf) < 0)
    {
      error (0, 0, _("Cannot fstat file %s.\n"), file_name);
      fclose (file);
      return 1;
    }

  /* Check that the file is large enough so that we can access the
     information.  We're only checking the size of the headers here.  */
  if (statbuf.st_size < sizeof (struct exec)
      || statbuf.st_size < sizeof (ElfW(Ehdr)))
    {
      error (0, 0, _("File %s is too small, not checked."), file_name);
      fclose (file);
      return 1;
    }

  file_contents = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED,
			fileno (file), 0);
  if (file_contents == MAP_FAILED)
    {
      error (0, 0, _("Cannot mmap file %s.\n"), file_name);
      fclose (file);
      return 1;
    }

  /* First check if this is an aout file.  */
  aout_header = (struct exec *) file_contents;
  if (N_MAGIC (*aout_header) == ZMAGIC
      || N_MAGIC (*aout_header) == QMAGIC)
    {
      /* Aout files don't have a soname, just return the name
         including the major number.  */
      char *copy, *major, *dot;
      copy = xstrdup (lib);
      major = strstr (copy, ".so.");
      if (major)
	{
	  dot = strstr (major + 4, ".");
	  if (dot)
	    *dot = '\0';
	}
      *soname = copy;
      *flag = FLAG_LIBC4;
      goto done;
    }

  elf_header = (ElfW(Ehdr) *) file_contents;
  if (elf_header->e_ident [EI_MAG0] != ELFMAG0
      || elf_header->e_ident [EI_MAG1] != ELFMAG1
      || elf_header->e_ident [EI_MAG2] != ELFMAG2
      || elf_header->e_ident [EI_MAG3] != ELFMAG3)
    {
      /* The file is neither ELF nor aout.  Check if it's a linker script,
	 like libc.so - otherwise complain.  */
      int len = statbuf.st_size;
      /* Only search the beginning of the file.  */
      if (len > 512)
	len = 512;
      if (memmem (file_contents, len, "GROUP", 5) == NULL
	  && memmem (file_contents, len, "GNU ld script", 13) == NULL)
	error (0, 0, _("%s is not an ELF file - it has the wrong magic bytes at the start.\n"),
	       file_name);
      ret = 1;
      goto done;
    }

  if (process_elf_file (file_name, lib, flag, soname, file_contents,
			statbuf.st_size))
    ret = 1;

 done:
  /* Clean up allocated memory and resources.  */
  munmap (file_contents, statbuf.st_size);
  fclose (file);

  return ret;
}

/* Get architecture specific version of process_elf_file.  */
#include "readelflib.c"
