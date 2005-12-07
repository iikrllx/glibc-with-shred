/* Copyright (C) 1996-1999, 2001, 2003, 2005 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.org>, 1996.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef _CHARMAP_H
#define _CHARMAP_H

#include <obstack.h>
#include <stdbool.h>

#include "repertoire.h"
#include "simple-hash.h"


struct width_rule
{
  struct charseq *from;
  struct charseq *to;
  unsigned int width;
};


struct charmap_t
{
  const char *code_set_name;
  const char *repertoiremap;
  int mb_cur_min;
  int mb_cur_max;

  struct width_rule *width_rules;
  size_t nwidth_rules;
  size_t nwidth_rules_max;
  unsigned int width_default;

  struct obstack mem_pool;
  hash_table char_table;
  hash_table byte_table;
  hash_table ucs4_table;
};


/* This is the structure used for entries in the hash table.  It represents
   the sequence of bytes used for the coded character.  */
struct charseq
{
  const char *name;
  uint32_t ucs4;
  int nbytes;
  unsigned char bytes[0];
};


/* True if the encoding is not ASCII compatible.  */
extern bool enc_not_ascii_compatible;


/* Prototypes for charmap handling functions.  */
extern struct charmap_t *charmap_read (const char *filename, int verbose,
				       int be_quiet, int use_default);

/* Return the value stored under the given key in the hashing table.  */
extern struct charseq *charmap_find_value (const struct charmap_t *charmap,
					   const char *name, size_t len);

/* Return symbol for given multibyte sequence.  */
extern struct charseq *charmap_find_symbol (const struct charmap_t *charmap,
					    const char *name, size_t len);

#endif /* charmap.h */
