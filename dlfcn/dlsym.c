/* Look up a symbol in a shared object loaded by `dlopen'.
   Copyright (C) 1995, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
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

#include <dlfcn.h>

struct dlsym_args
{
  /* The arguments to dlsym_doit.  */
  void *handle;
  const char *name;
  void *who;

  /* The return value of dlsym_doit.  */
  void *sym;
};

static void
dlsym_doit (void *a)
{
  struct dlsym_args *args = (struct dlsym_args *) a;

  args->sym = _dl_sym (args->handle, args->name, args->who);
}


void *
dlsym (void *handle, const char *name)
{
  struct dlsym_args args;
  args.who = __builtin_return_address (0);
  args.handle = handle;
  args.name = name;

  return (_dlerror_run (dlsym_doit, &args) ? NULL : args.sym);
}
