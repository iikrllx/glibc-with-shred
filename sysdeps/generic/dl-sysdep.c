/* Operating system support for run-time dynamic linker.  Generic Unix version.
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

#include <elf.h>
#include <entry.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>


extern int _dl_argc;
extern char **_dl_argv;
extern char **_environ;
extern size_t _dl_pagesize;
extern void _end;
extern void ENTRY_POINT (void);

int __libc_enable_secure;
int __libc_multiple_libcs;	/* Defining this here avoids the inclusion
				   of init-first.  */

ElfW(Addr)
_dl_sysdep_start (void **start_argptr,
		  void (*dl_main) (const ElfW(Phdr) *phdr, ElfW(Word) phnum,
				   ElfW(Addr) *user_entry))
{
  const ElfW(Phdr) *phdr = NULL;
  ElfW(Word) phnum = 0;
  ElfW(Addr) user_entry;
  ElfW(auxv_t) *av;
  uid_t uid = 0;
  uid_t euid = 0;
  gid_t gid = 0;
  gid_t egid = 0;
  unsigned int seen;

  user_entry = (ElfW(Addr)) &ENTRY_POINT;
  _dl_argc = *(long *) start_argptr;
  _dl_argv = (char **) start_argptr + 1;
  _environ = &_dl_argv[_dl_argc + 1];
  start_argptr = (void **) _environ;
  while (*start_argptr)
    ++start_argptr;

  seen = 0;
#define M(type) (1 << (type))

  for (av = (void *) ++start_argptr;
       av->a_type != AT_NULL;
       seen |= M ((++av)->a_type))
    switch (av->a_type)
      {
      case AT_PHDR:
	phdr = av->a_un.a_ptr;
	break;
      case AT_PHNUM:
	phnum = av->a_un.a_val;
	break;
      case AT_PAGESZ:
	_dl_pagesize = av->a_un.a_val;
	break;
      case AT_ENTRY:
	user_entry = av->a_un.a_val;
	break;
      case AT_UID:
	uid = av->a_un.a_val;
	break;
      case AT_GID:
	gid = av->a_un.a_val;
	break;
      case AT_EUID:
	euid = av->a_un.a_val;
	break;
      case AT_EGID:
	egid = av->a_un.a_val;
	break;
      }

  /* Linux doesn't provide us with any of these values on the stack
     when the dynamic linker is run directly as a program.  */

#define SEE(UID, uid) if ((seen & M (AT_##UID)) == 0) uid = __get##uid ()
  SEE (UID, uid);
  SEE (GID, gid);
  SEE (EUID, euid);
  SEE (EGID, egid);


  __libc_enable_secure = uid != euid || gid != egid;

#ifdef DL_SYSDEP_INIT
  DL_SYSDEP_INIT;
#endif

  if (__sbrk (0) == &_end)
    {
      /* The dynamic linker was run as a program, and so the initial break
	 starts just after our bss, at &_end.  The malloc in dl-minimal.c
	 will consume the rest of this page, so tell the kernel to move the
	 break up that far.  When the user program examines its break, it
	 will see this new value and not clobber our data.  */
      size_t pg = __getpagesize ();

      __sbrk (pg - ((&_end - (void *) 0) & (pg - 1)));
    }

  (*dl_main) (phdr, phnum, &user_entry);
  return user_entry;
}

void
_dl_sysdep_start_cleanup (void)
{
}
