/* Thread-local storage descriptor handling in the ELF dynamic linker.
   i386 version.
   Copyright (C) 2005-2020 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _I386_DL_TLSDESC_H
# define _I386_DL_TLSDESC_H 1

/* Type used to represent a TLS descriptor in the GOT.  */
struct tlsdesc
{
  ptrdiff_t __attribute__ ((regparm (1))) (*entry) (struct tlsdesc *);
  void *arg;
};

typedef struct dl_tls_index
{
  unsigned long int ti_module;
  unsigned long int ti_offset;
} tls_index;

/* Type used as the argument in a TLS descriptor for a symbol that
   needs dynamic TLS offsets.  */
struct tlsdesc_dynamic_arg
{
  tls_index tlsinfo;
  size_t gen_count;
};

extern ptrdiff_t attribute_hidden __attribute__ ((regparm (1)))
  _dl_tlsdesc_return (struct tlsdesc *),
  _dl_tlsdesc_undefweak (struct tlsdesc *),
  _dl_tlsdesc_resolve_abs_plus_addend (struct tlsdesc *),
  _dl_tlsdesc_resolve_rel (struct tlsdesc *),
  _dl_tlsdesc_resolve_rela (struct tlsdesc *),
  _dl_tlsdesc_resolve_hold (struct tlsdesc *);

# ifdef SHARED
extern void *_dl_make_tlsdesc_dynamic (struct link_map *map,
				       size_t ti_offset) attribute_hidden;

extern ptrdiff_t attribute_hidden __attribute__ ((regparm (1)))
  _dl_tlsdesc_dynamic (struct tlsdesc *);
# endif

#endif
