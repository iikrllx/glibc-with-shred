/* Load a shared object at run time.
   Copyright (C) 1995,96,97,98,99,2000,2003,2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <dlfcn.h>
#include <errno.h>
#include <libintl.h>
#include <stddef.h>
#include <ldsodefs.h>

struct dlmopen_args
{
  /* Namespace ID.  */
  Lmid_t nsid;
  /* The arguments for dlopen_doit.  */
  const char *file;
  int mode;
  /* The return value of dlopen_doit.  */
  void *new;
  /* Address of the caller.  */
  const void *caller;
};

static void
dlmopen_doit (void *a)
{
  struct dlmopen_args *args = (struct dlmopen_args *) a;

  /* Non-shared code has no support for multiple namespaces.  */
  if (args->nsid != LM_ID_BASE)
#ifdef SHARED
    /* If trying to open the link map for the main executable the namespace
       must be the main one.  */
    if (args->file == NULL)
#endif
      GLRO(dl_signal_error) (EINVAL, NULL, NULL, N_("invalid namespace"));

  args->new = _dl_open (args->file ?: "", args->mode | __RTLD_DLOPEN,
			args->caller, args->nsid);
}


void *
dlmopen (Lmid_t nsid, const char *file, int mode)
{
  struct dlmopen_args args;
  args.nsid = nsid;
  args.file = file;
  args.mode = mode;
  args.caller = RETURN_ADDRESS (0);

  return _dlerror_run (dlmopen_doit, &args) ? NULL : args.new;
}
static_link_warning (dlmopen)
