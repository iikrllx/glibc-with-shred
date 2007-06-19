/* Get loaded objects program headers.
   Copyright (C) 2001,2002,2003,2004,2006,2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jakub Jelinek <jakub@redhat.com>, 2001.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <ldsodefs.h>
#include <stddef.h>
#include <bits/libc-lock.h>

static void
cancel_handler (void *arg __attribute__((unused)))
{
  __rtld_lock_unlock_recursive (GL(dl_load_lock));
}

hidden_proto (__dl_iterate_phdr)
int
__dl_iterate_phdr (int (*callback) (struct dl_phdr_info *info,
				    size_t size, void *data), void *data)
{
  struct link_map *l;
  struct dl_phdr_info info;
  int ret = 0;

  /* Make sure we are alone.  */
  __rtld_lock_lock_recursive (GL(dl_load_lock));
  __libc_cleanup_push (cancel_handler, 0);

  /* We have to determine the namespace of the caller since this determines
     which namespace is reported.  */
  const void *caller = RETURN_ADDRESS (0);
  size_t nloaded = GL(dl_ns)[0]._ns_nloaded;
  Lmid_t ns = 0;
  for (Lmid_t cnt = DL_NNS - 1; cnt > 0; --cnt)
    for (struct link_map *l = GL(dl_ns)[cnt]._ns_loaded; l; l = l->l_next)
      {
	/* We have to count the total number of loaded objects.  */
	nloaded += GL(dl_ns)[cnt]._ns_nloaded;

	if (caller >= (const void *) l->l_map_start
	    && caller < (const void *) l->l_map_end
	    && (l->l_contiguous
		|| _dl_addr_inside_object (l, (ElfW(Addr)) caller)))
	  ns = cnt;
      }

  for (l = GL(dl_ns)[ns]._ns_loaded; l != NULL; l = l->l_next)
    {
      info.dlpi_addr = l->l_addr;
      info.dlpi_name = l->l_name;
      info.dlpi_phdr = l->l_phdr;
      info.dlpi_phnum = l->l_phnum;
      info.dlpi_adds = GL(dl_load_adds);
      info.dlpi_subs = GL(dl_load_adds) - nloaded;
      info.dlpi_tls_modid = 0;
      info.dlpi_tls_data = NULL;
      info.dlpi_tls_modid = l->l_tls_modid;
      if (info.dlpi_tls_modid != 0)
	info.dlpi_tls_data = _dl_tls_get_addr_soft (l);
      ret = callback (&info, sizeof (struct dl_phdr_info), data);
      if (ret)
	break;
    }

  /* Release the lock.  */
  __libc_cleanup_pop (0);
  __rtld_lock_unlock_recursive (GL(dl_load_lock));

  return ret;
}
hidden_def (__dl_iterate_phdr)

#ifdef SHARED

weak_alias (__dl_iterate_phdr, dl_iterate_phdr);

#else

/* dl-support.c defines these and initializes them early on.  */
extern ElfW(Phdr) *_dl_phdr;
extern size_t _dl_phnum;

int
dl_iterate_phdr (int (*callback) (struct dl_phdr_info *info,
				  size_t size, void *data), void *data)
{
  if (_dl_phnum != 0)
    {
      /* This entry describes this statically-linked program itself.  */
      struct dl_phdr_info info;
      int ret;
      info.dlpi_addr = 0;
      info.dlpi_name = "";
      info.dlpi_phdr = _dl_phdr;
      info.dlpi_phnum = _dl_phnum;
      info.dlpi_adds = GL(dl_load_adds);
      info.dlpi_subs = GL(dl_load_adds) - GL(dl_ns)[LM_ID_BASE]._ns_nloaded;
      ret = (*callback) (&info, sizeof (struct dl_phdr_info), data);
      if (ret)
	return ret;
    }

  return __dl_iterate_phdr (callback, data);
}


#endif
