/* Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#ifndef _REPERTOIREMAP_H
#define _REPERTOIREMAP_H	1

#include <obstack.h>
#include <stdint.h>

#include "charmap.h"
#include "simple-hash.h"

struct repertoire_t
{
  const char *name;
  struct obstack mem_pool;
  hash_table char_table;
  hash_table reverse_table;
  hash_table seq_table;
};


/* We need one value to mark the error case.  Let's use 0xffffffff.
   I.e., it is placed in the last page of ISO 10646.  For now only the
   first is used and we have plenty of room.  */
#define ILLEGAL_CHAR_VALUE ((uint32_t) 0xffffffffu)

/* Another value is needed to signal that a value is not yet determined.  */
#define UNINITIALIZED_CHAR_VALUE ((uint32_t) 0xfffffffeu)


/* Prototypes for repertoire map handling functions.  */
extern struct repertoire_t *repertoire_read (const char *filename);

/* Report missing repertoire map.  */
extern void repertoire_complain (const char *name);

/* Return UCS4 value of character with given NAME.  */
extern uint32_t repertoire_find_value (const struct repertoire_t *repertoire,
				       const char *name, size_t len);

/* Return symbol for given UCS4 value.  */
extern const char *repertoire_find_symbol (const struct repertoire_t *repertoire,
					   uint32_t ucs);

/* Query the has table to memoize mapping from UCS4 to byte sequences.  */
extern struct charseq *repertoire_find_seq (const struct repertoire_t *rep,
					    uint32_t ucs);

#endif /* repertoiremap.h */
