/* Copyright (C) 1995, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.org>, 1995.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <alloca.h>
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <obstack.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <sys/uio.h>

#include "charmap.h"
#include "localeinfo.h"
#include "langinfo.h"
#include "linereader.h"
#include "locfile-token.h"
#include "locfile.h"
#include "localedef.h"

#include <assert.h>


/* These are the extra bits not in wctype.h since these are not preallocated
   classes.  */
#define _ISwspecial1	(1 << 29)
#define _ISwspecial2	(1 << 30)
#define _ISwspecial3	(1 << 31)


/* The bit used for representing a special class.  */
#define BITPOS(class) ((class) - tok_upper)
#define BIT(class) (_ISbit (BITPOS (class)))
#define BITw(class) (_ISwbit (BITPOS (class)))

#define ELEM(ctype, collection, idx, value)				      \
  *find_idx (ctype, &ctype->collection idx, &ctype->collection##_max idx,     \
	     &ctype->collection##_act idx, value)


/* To be compatible with former implementations we for now restrict
   the number of bits for character classes to 16.  When compatibility
   is not necessary anymore increase the number to 32.  */
#define char_class_t uint16_t
#define char_class32_t uint32_t


/* Type to describe a transliteration action.  We have a possibly
   multiple character from-string and a set of multiple character
   to-strings.  All are 32bit values since this is what is used in
   the gconv functions.  */
struct translit_to_t
{
  uint32_t *str;

  struct translit_to_t *next;
};

struct translit_t
{
  uint32_t *from;

  struct translit_to_t *to;

  struct translit_t *next;
};


/* The real definition of the struct for the LC_CTYPE locale.  */
struct locale_ctype_t
{
  uint32_t *charnames;
  size_t charnames_max;
  size_t charnames_act;

  struct repertoire_t *repertoire;

  /* We will allow up to 8 * sizeof (uint32_t) character classes.  */
#define MAX_NR_CHARCLASS (8 * sizeof (uint32_t))
  size_t nr_charclass;
  const char *classnames[MAX_NR_CHARCLASS];
  uint32_t last_class_char;
  uint32_t class256_collection[256];
  uint32_t *class_collection;
  size_t class_collection_max;
  size_t class_collection_act;
  uint32_t class_done;

  struct charseq **mbdigits;
  size_t mbdigits_act;
  size_t mbdigits_max;
  uint32_t *wcdigits;
  size_t wcdigits_act;
  size_t wcdigits_max;

  struct charseq *mboutdigits[10];
  uint32_t wcoutdigits[10];
  size_t outdigits_act;

  /* If the following number ever turns out to be too small simply
     increase it.  But I doubt it will.  --drepper@gnu */
#define MAX_NR_CHARMAP 16
  const char *mapnames[MAX_NR_CHARMAP];
  uint32_t *map_collection[MAX_NR_CHARMAP];
  uint32_t map256_collection[2][256];
  size_t map_collection_max[MAX_NR_CHARMAP];
  size_t map_collection_act[MAX_NR_CHARMAP];
  size_t map_collection_nr;
  size_t last_map_idx;
  int tomap_done[MAX_NR_CHARMAP];

  /* Transliteration information.  */
  const char *translit_copy_locale;
  const char *translit_copy_repertoire;
  struct translit_t *translit;

  /* The arrays for the binary representation.  */
  uint32_t plane_size;
  uint32_t plane_cnt;
  char_class_t *ctype_b;
  char_class32_t *ctype32_b;
  uint32_t *names;
  uint32_t **map;
  uint32_t *class_name_ptr;
  uint32_t *map_name_ptr;
  unsigned char *width;
  uint32_t mb_cur_max;
  const char *codeset_name;
  uint32_t translit_hash_size;
  uint32_t translit_hash_layers;
  uint32_t *translit_from_idx;
  uint32_t *translit_from_tbl;
  uint32_t *translit_to_idx;
  uint32_t *translit_to_tbl;
  size_t translit_idx_size;
  size_t translit_from_tbl_size;
  size_t translit_to_tbl_size;

  struct obstack mem_pool;
};


#define obstack_chunk_alloc xmalloc
#define obstack_chunk_free free


/* Prototypes for local functions.  */
static void ctype_startup (struct linereader *lr, struct localedef_t *locale,
			   struct charmap_t *charmap, int ignore_content);
static void ctype_class_new (struct linereader *lr,
			     struct locale_ctype_t *ctype, const char *name);
static void ctype_map_new (struct linereader *lr,
			   struct locale_ctype_t *ctype,
			   const char *name, struct charmap_t *charmap);
static uint32_t *find_idx (struct locale_ctype_t *ctype, uint32_t **table,
			   size_t *max, size_t *act, unsigned int idx);
static void set_class_defaults (struct locale_ctype_t *ctype,
				struct charmap_t *charmap,
				struct repertoire_t *repertoire);
static void allocate_arrays (struct locale_ctype_t *ctype,
			     struct charmap_t *charmap,
			     struct repertoire_t *repertoire);


static const char *longnames[] =
{
  "zero", "one", "two", "three", "four",
  "five", "six", "seven", "eight", "nine"
};
static const unsigned char digits[] = "0123456789";


static void
ctype_startup (struct linereader *lr, struct localedef_t *locale,
	       struct charmap_t *charmap, int ignore_content)
{
  unsigned int cnt;
  struct locale_ctype_t *ctype;

  if (!ignore_content)
    {
      /* Allocate the needed room.  */
      locale->categories[LC_CTYPE].ctype = ctype =
	(struct locale_ctype_t *) xcalloc (1, sizeof (struct locale_ctype_t));

      /* We have seen no names yet.  */
      ctype->charnames_max = charmap->mb_cur_max == 1 ? 256 : 512;
      ctype->charnames =
	(unsigned int *) xmalloc (ctype->charnames_max
				  * sizeof (unsigned int));
      for (cnt = 0; cnt < 256; ++cnt)
	ctype->charnames[cnt] = cnt;
      ctype->charnames_act = 256;

      /* Fill character class information.  */
      ctype->last_class_char = ILLEGAL_CHAR_VALUE;
      /* The order of the following instructions determines the bit
	 positions!  */
      ctype_class_new (lr, ctype, "upper");
      ctype_class_new (lr, ctype, "lower");
      ctype_class_new (lr, ctype, "alpha");
      ctype_class_new (lr, ctype, "digit");
      ctype_class_new (lr, ctype, "xdigit");
      ctype_class_new (lr, ctype, "space");
      ctype_class_new (lr, ctype, "print");
      ctype_class_new (lr, ctype, "graph");
      ctype_class_new (lr, ctype, "blank");
      ctype_class_new (lr, ctype, "cntrl");
      ctype_class_new (lr, ctype, "punct");
      ctype_class_new (lr, ctype, "alnum");
      /* The following are extensions from ISO 14652.  */
      ctype_class_new (lr, ctype, "left_to_right");
      ctype_class_new (lr, ctype, "right_to_left");
      ctype_class_new (lr, ctype, "num_terminator");
      ctype_class_new (lr, ctype, "num_separator");
      ctype_class_new (lr, ctype, "segment_separator");
      ctype_class_new (lr, ctype, "block_separator");
      ctype_class_new (lr, ctype, "direction_control");
      ctype_class_new (lr, ctype, "sym_swap_layout");
      ctype_class_new (lr, ctype, "char_shape_selector");
      ctype_class_new (lr, ctype, "num_shape_selector");
      ctype_class_new (lr, ctype, "non_spacing");
      ctype_class_new (lr, ctype, "non_spacing_level3");
      ctype_class_new (lr, ctype, "normal_connect");
      ctype_class_new (lr, ctype, "r_connect");
      ctype_class_new (lr, ctype, "no_connect");
      ctype_class_new (lr, ctype, "no_connect-space");
      ctype_class_new (lr, ctype, "vowel_connect");

      ctype->class_collection_max = charmap->mb_cur_max == 1 ? 256 : 512;
      ctype->class_collection
	= (uint32_t *) xcalloc (sizeof (unsigned long int),
				ctype->class_collection_max);
      ctype->class_collection_act = 256;

      /* Fill character map information.  */
      ctype->map_collection_nr = 0;
      ctype->last_map_idx = MAX_NR_CHARMAP;
      ctype_map_new (lr, ctype, "toupper", charmap);
      ctype_map_new (lr, ctype, "tolower", charmap);
      ctype_map_new (lr, ctype, "tosymmetric", charmap);

      /* Fill first 256 entries in `toXXX' arrays.  */
      for (cnt = 0; cnt < 256; ++cnt)
	{
	  ctype->map_collection[0][cnt] = cnt;
	  ctype->map_collection[1][cnt] = cnt;
	  ctype->map_collection[2][cnt] = cnt;
	  ctype->map256_collection[0][cnt] = cnt;
	  ctype->map256_collection[1][cnt] = cnt;
	}

      obstack_init (&ctype->mem_pool);
    }
}


void
ctype_finish (struct localedef_t *locale, struct charmap_t *charmap)
{
  /* See POSIX.2, table 2-6 for the meaning of the following table.  */
#define NCLASS 12
  static const struct
  {
    const char *name;
    const char allow[NCLASS];
  }
  valid_table[NCLASS] =
  {
    /* The order is important.  See token.h for more information.
       M = Always, D = Default, - = Permitted, X = Mutually exclusive  */
    { "upper",  "--MX-XDDXXX-" },
    { "lower",  "--MX-XDDXXX-" },
    { "alpha",  "---X-XDDXXX-" },
    { "digit",  "XXX--XDDXXX-" },
    { "xdigit", "-----XDDXXX-" },
    { "space",  "XXXXX------X" },
    { "print",  "---------X--" },
    { "graph",  "---------X--" },
    { "blank",  "XXXXXM-----X" },
    { "cntrl",  "XXXXX-XX--XX" },
    { "punct",  "XXXXX-DD-X-X" },
    { "alnum",  "-----XDDXXX-" }
  };
  size_t cnt;
  int cls1, cls2;
  uint32_t space_value;
  struct charseq *space_seq;
  struct locale_ctype_t *ctype = locale->categories[LC_CTYPE].ctype;
  int warned;

  /* Now resolve copying and also handle completely missing definitions.  */
  if (ctype == NULL)
    {
      /* First see whether we were supposed to copy.  If yes, find the
	 actual definition.  */
      if (locale->copy_name[LC_CTYPE] != NULL)
	{
	  /* Find the copying locale.  This has to happen transitively since
	     the locale we are copying from might also copying another one.  */
	  struct localedef_t *from = locale;

	  do
	    from = find_locale (LC_CTYPE, from->copy_name[LC_CTYPE],
				from->repertoire_name, charmap);
	  while (from->categories[LC_CTYPE].ctype == NULL
		 && from->copy_name[LC_CTYPE] != NULL);

	  ctype = locale->categories[LC_CTYPE].ctype
	    = from->categories[LC_CTYPE].ctype;
	}

      /* If there is still no definition issue an warning and create an
	 empty one.  */
      if (ctype == NULL)
	{
	  error (0, 0, _("No definition for %s category found"), "LC_CTYPE");
	  ctype_startup (NULL, locale, charmap, 0);
	  ctype = locale->categories[LC_CTYPE].ctype;
	}
    }

  /* Set default value for classes not specified.  */
  set_class_defaults (ctype, charmap, ctype->repertoire);

  /* Check according to table.  */
  for (cnt = 0; cnt < ctype->class_collection_max; ++cnt)
    {
      uint32_t tmp = ctype->class_collection[cnt];

      if (tmp != 0)
	{
	  for (cls1 = 0; cls1 < NCLASS; ++cls1)
	    if ((tmp & _ISwbit (cls1)) != 0)
	      for (cls2 = 0; cls2 < NCLASS; ++cls2)
		if (valid_table[cls1].allow[cls2] != '-')
		  {
		    int eq = (tmp & _ISwbit (cls2)) != 0;
		    switch (valid_table[cls1].allow[cls2])
		      {
		      case 'M':
			if (!eq)
			  {
			    uint32_t value = ctype->charnames[cnt];

			    if (!be_quiet)
			      error (0, 0, _("\
character L'\\u%0*x' in class `%s' must be in class `%s'"),
				     value > 0xffff ? 8 : 4, value,
				     valid_table[cls1].name,
				     valid_table[cls2].name);
			  }
			break;

		      case 'X':
			if (eq)
			  {
			    uint32_t value = ctype->charnames[cnt];

			    if (!be_quiet)
			      error (0, 0, _("\
character L'\\u%0*x' in class `%s' must not be in class `%s'"),
				     value > 0xffff ? 8 : 4, value,
				     valid_table[cls1].name,
				     valid_table[cls2].name);
			  }
			break;

		      case 'D':
			ctype->class_collection[cnt] |= _ISwbit (cls2);
			break;

		      default:
			error (5, 0, _("internal error in %s, line %u"),
			       __FUNCTION__, __LINE__);
		      }
		  }
	}
    }

  for (cnt = 0; cnt < 256; ++cnt)
    {
      uint32_t tmp = ctype->class256_collection[cnt];

      if (tmp != 0)
	{
	  for (cls1 = 0; cls1 < NCLASS; ++cls1)
	    if ((tmp & _ISbit (cls1)) != 0)
	      for (cls2 = 0; cls2 < NCLASS; ++cls2)
		if (valid_table[cls1].allow[cls2] != '-')
		  {
		    int eq = (tmp & _ISbit (cls2)) != 0;
		    switch (valid_table[cls1].allow[cls2])
		      {
		      case 'M':
			if (!eq)
			  {
			    char buf[17];

			    sprintf (buf, "\\%o", cnt);

			    if (!be_quiet)
			      error (0, 0, _("\
character '%s' in class `%s' must be in class `%s'"),
				     buf, valid_table[cls1].name,
				     valid_table[cls2].name);
			  }
			break;

		      case 'X':
			if (eq)
			  {
			    char buf[17];

			    sprintf (buf, "\\%o", cnt);

			    if (!be_quiet)
			      error (0, 0, _("\
character '%s' in class `%s' must not be in class `%s'"),
				     buf, valid_table[cls1].name,
				     valid_table[cls2].name);
			  }
			break;

		      case 'D':
			ctype->class256_collection[cnt] |= _ISbit (cls2);
			break;

		      default:
			error (5, 0, _("internal error in %s, line %u"),
			       __FUNCTION__, __LINE__);
		      }
		  }
	}
    }

  /* ... and now test <SP> as a special case.  */
  space_value = repertoire_find_value (ctype->repertoire, "SP", 2);
  if (space_value == ILLEGAL_CHAR_VALUE)
    {
      if (!be_quiet)
	error (0, 0, _("character <SP> not defined in character map"));
    }
  else if (((cnt = BITPOS (tok_space),
	     (ELEM (ctype, class_collection, , space_value)
	      & BITw (tok_space)) == 0)
	    || (cnt = BITPOS (tok_blank),
		(ELEM (ctype, class_collection, , space_value)
		 & BITw (tok_blank)) == 0)))
    {
      if (!be_quiet)
	error (0, 0, _("<SP> character not in class `%s'"),
	       valid_table[cnt].name);
    }
  else if (((cnt = BITPOS (tok_punct),
	     (ELEM (ctype, class_collection, , space_value)
	      & BITw (tok_punct)) != 0)
	    || (cnt = BITPOS (tok_graph),
		(ELEM (ctype, class_collection, , space_value)
		 & BITw (tok_graph))
		!= 0)))
    {
      if (!be_quiet)
	error (0, 0, _("<SP> character must not be in class `%s'"),
	       valid_table[cnt].name);
    }
  else
    ELEM (ctype, class_collection, , space_value) |= BITw (tok_print);

  space_seq = charmap_find_value (charmap, "SP", 2);
  if (space_seq == NULL || space_seq->nbytes != 1)
    {
      if (!be_quiet)
	error (0, 0, _("character <SP> not defined in character map"));
    }
  else if (((cnt = BITPOS (tok_space),
	     (ctype->class256_collection[space_seq->bytes[0]]
	      & BIT (tok_space)) == 0)
	    || (cnt = BITPOS (tok_blank),
		(ctype->class256_collection[space_seq->bytes[0]]
		 & BIT (tok_blank)) == 0)))
    {
      if (!be_quiet)
	error (0, 0, _("<SP> character not in class `%s'"),
	       valid_table[cnt].name);
    }
  else if (((cnt = BITPOS (tok_punct),
	     (ctype->class256_collection[space_seq->bytes[0]]
	      & BIT (tok_punct)) != 0)
	    || (cnt = BITPOS (tok_graph),
		(ctype->class256_collection[space_seq->bytes[0]]
		 & BIT (tok_graph)) != 0)))
    {
      if (!be_quiet)
	error (0, 0, _("<SP> character must not be in class `%s'"),
	       valid_table[cnt].name);
    }
  else
    ctype->class256_collection[space_seq->bytes[0]] |= BIT (tok_print);

  /* Now that the tests are done make sure the name array contains all
     characters which are handled in the WIDTH section of the
     character set definition file.  */
  if (charmap->width_rules != NULL)
    for (cnt = 0; cnt < charmap->nwidth_rules; ++cnt)
      {
#if 0
	size_t inner;
	for (inner = charmap->width_rules[cnt].from;
	     inner <= charmap->width_rules[cnt].to; ++inner)
	  (void) find_idx (ctype, NULL, NULL, NULL, inner);
#else
	/* XXX Handle width.  We must convert from the charseq to the
           repertoire value */
	abort ();
#endif
      }

  /* There must be a multiple of 10 digits.  */
  if (ctype->mbdigits_act % 10 != 0)
    {
      assert (ctype->mbdigits_act == ctype->wcdigits_act);
      ctype->wcdigits_act -= ctype->mbdigits_act % 10;
      ctype->mbdigits_act -= ctype->mbdigits_act % 10;
      error (0, 0, _("`digit' category has not entries in groups of ten"));
    }

  /* Check the input digits.  There must be a multiple of ten available.
     In each group I could be that one or the other character is missing.
     In this case the whole group must be removed.  */
  cnt = 0;
  while (cnt < ctype->mbdigits_act)
    {
      size_t inner;
      for (inner = 0; inner < 10; ++inner)
	if (ctype->mbdigits[cnt + inner] == NULL)
	  break;

      if (inner == 10)
	cnt += 10;
      else
	{
	  /* Remove the group.  */
	  memmove (&ctype->mbdigits[cnt], &ctype->mbdigits[cnt + 10],
		   ((ctype->wcdigits_act - cnt - 10)
		    * sizeof (ctype->mbdigits[0])));
	  ctype->mbdigits_act -= 10;
	}
    }

  /* If no input digits are given use the default.  */
  if (ctype->mbdigits_act == 0)
    {
      if (ctype->mbdigits_max == 0)
	{
	  ctype->mbdigits = obstack_alloc (&charmap->mem_pool,
					   10 * sizeof (struct charseq *));
	  ctype->mbdigits_max = 10;
	}

      for (cnt = 0; cnt < 10; ++cnt)
	{
	  ctype->mbdigits[cnt] = charmap_find_symbol (charmap,
						      digits + cnt, 1);
	  if (ctype->mbdigits[cnt] == NULL)
	    {
	      ctype->mbdigits[cnt] = charmap_find_symbol (charmap,
							  longnames[cnt],
							  strlen (longnames[cnt]));
	      if (ctype->mbdigits[cnt] == NULL)
		{
		  /* Hum, this ain't good.  */
		  error (0, 0, _("\
no input digits defined and none of the standard names in the charmap"));

		  ctype->mbdigits[cnt] = obstack_alloc (&charmap->mem_pool,
							sizeof (struct charseq) + 1);

		  /* This is better than nothing.  */
		  ctype->mbdigits[cnt]->bytes[0] = digits[cnt];
		  ctype->mbdigits[cnt]->nbytes = 1;
		}
	    }
	}

      ctype->mbdigits_act = 10;
    }

  /* Check the wide character input digits.  There must be a multiple
     of ten available.  In each group I could be that one or the other
     character is missing.  In this case the whole group must be
     removed.  */
  cnt = 0;
  while (cnt < ctype->wcdigits_act)
    {
      size_t inner;
      for (inner = 0; inner < 10; ++inner)
	if (ctype->wcdigits[cnt + inner] == ILLEGAL_CHAR_VALUE)
	  break;

      if (inner == 10)
	cnt += 10;
      else
	{
	  /* Remove the group.  */
	  memmove (&ctype->wcdigits[cnt], &ctype->wcdigits[cnt + 10],
		   ((ctype->wcdigits_act - cnt - 10)
		    * sizeof (ctype->wcdigits[0])));
	  ctype->wcdigits_act -= 10;
	}
    }

  /* If no input digits are given use the default.  */
  if (ctype->wcdigits_act == 0)
    {
      if (ctype->wcdigits_max == 0)
	{
	  ctype->wcdigits = obstack_alloc (&charmap->mem_pool,
					   10 * sizeof (uint32_t));
	  ctype->wcdigits_max = 10;
	}

      for (cnt = 0; cnt < 10; ++cnt)
	ctype->wcdigits[cnt] = L'0' + cnt;

      ctype->mbdigits_act = 10;
    }

  /* Check the outdigits.  */
  warned = 0;
  for (cnt = 0; cnt < 10; ++cnt)
    if (ctype->mboutdigits[cnt] == NULL)
      {
	static struct charseq replace[2];

	if (!warned)
	  {
	    error (0, 0, _("\
not all characters used in `outdigit' are available in the charmap"));
	    warned = 1;
	  }

	replace[0].nbytes = 1;
	replace[0].bytes[0] = '?';
	replace[0].bytes[1] = '\0';
	ctype->mboutdigits[cnt] = &replace[0];
      }

  warned = 0;
  for (cnt = 0; cnt < 10; ++cnt)
    if (ctype->wcoutdigits[cnt] == 0)
      {
	if (!warned)
	  {
	    error (0, 0, _("\
not all characters used in `outdigit' are available in the repertoire"));
	    warned = 1;
	  }

	ctype->wcoutdigits[cnt] = L'?';
      }
}


void
ctype_output (struct localedef_t *locale, struct charmap_t *charmap,
	      const char *output_path)
{
  struct locale_ctype_t *ctype = locale->categories[LC_CTYPE].ctype;
  const size_t nelems = (_NL_ITEM_INDEX (_NL_NUM_LC_CTYPE)
			 + 2 * (ctype->map_collection_nr - 2));
  struct iovec iov[2 + nelems + ctype->nr_charclass
		  + ctype->map_collection_nr];
  struct locale_file data;
  uint32_t idx[nelems + 1];
  size_t elem, cnt, offset, total;
  char *cp;

  /* Now prepare the output: Find the sizes of the table we can use.  */
  allocate_arrays (ctype, charmap, ctype->repertoire);

  data.magic = LIMAGIC (LC_CTYPE);
  data.n = nelems;
  iov[0].iov_base = (void *) &data;
  iov[0].iov_len = sizeof (data);

  iov[1].iov_base = (void *) idx;
  iov[1].iov_len = sizeof (idx);

  idx[0] = iov[0].iov_len + iov[1].iov_len;
  offset = 0;

  for (elem = 0; elem < nelems; ++elem)
    {
      if (elem < _NL_ITEM_INDEX (_NL_NUM_LC_CTYPE))
	switch (elem)
	  {
#define CTYPE_DATA(name, base, len)					      \
	  case _NL_ITEM_INDEX (name):					      \
	    iov[2 + elem + offset].iov_base = (base);			      \
	    iov[2 + elem + offset].iov_len = (len);			      \
	    if (elem + 1 < nelems)					      \
	      idx[elem + 1] = idx[elem] + iov[2 + elem + offset].iov_len;     \
	    break

	  CTYPE_DATA (_NL_CTYPE_CLASS,
		      ctype->ctype_b,
		      (256 + 128) * sizeof (char_class_t));

	  CTYPE_DATA (_NL_CTYPE_TOUPPER,
		      ctype->map[0],
		      (ctype->plane_size * ctype->plane_cnt + 128)
		      * sizeof (uint32_t));
	  CTYPE_DATA (_NL_CTYPE_TOLOWER,
		      ctype->map[1],
		      (ctype->plane_size * ctype->plane_cnt + 128)
		      * sizeof (uint32_t));

	  CTYPE_DATA (_NL_CTYPE_CLASS32,
		      ctype->ctype32_b,
		      (ctype->plane_size * ctype->plane_cnt
		       * sizeof (char_class32_t)));

	  CTYPE_DATA (_NL_CTYPE_NAMES,
		      ctype->names, (ctype->plane_size * ctype->plane_cnt
				     * sizeof (uint32_t)));

	  CTYPE_DATA (_NL_CTYPE_TRANSLIT_HASH_SIZE,
		      &ctype->translit_hash_size, sizeof (uint32_t));
	  CTYPE_DATA (_NL_CTYPE_TRANSLIT_HASH_LAYERS,
		      &ctype->translit_hash_layers, sizeof (uint32_t));

	  CTYPE_DATA (_NL_CTYPE_TRANSLIT_FROM_IDX,
		      ctype->translit_from_idx,
		      ctype->translit_idx_size);

	  CTYPE_DATA (_NL_CTYPE_TRANSLIT_FROM_TBL,
		      ctype->translit_from_tbl,
		      ctype->translit_from_tbl_size);

	  CTYPE_DATA (_NL_CTYPE_TRANSLIT_TO_IDX,
		      ctype->translit_to_idx,
		      ctype->translit_idx_size);

	  CTYPE_DATA (_NL_CTYPE_TRANSLIT_TO_TBL,
		      ctype->translit_to_tbl, ctype->translit_to_tbl_size);

	  CTYPE_DATA (_NL_CTYPE_HASH_SIZE,
		      &ctype->plane_size, sizeof (uint32_t));
	  CTYPE_DATA (_NL_CTYPE_HASH_LAYERS,
		      &ctype->plane_cnt, sizeof (uint32_t));

	  case _NL_ITEM_INDEX (_NL_CTYPE_CLASS_NAMES):
	    /* The class name array.  */
	    total = 0;
	    for (cnt = 0; cnt < ctype->nr_charclass; ++cnt, ++offset)
	      {
		iov[2 + elem + offset].iov_base
		  = (void *) ctype->classnames[cnt];
		iov[2 + elem + offset].iov_len
		  = strlen (ctype->classnames[cnt]) + 1;
		total += iov[2 + elem + offset].iov_len;
	      }
	    iov[2 + elem + offset].iov_base = (void *) "\0\0\0";
	    iov[2 + elem + offset].iov_len = 1 + (4 - ((total + 1) % 4));
	    total += 1 + (4 - ((total + 1) % 4));

	    idx[elem + 1] = idx[elem] + total;
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_MAP_NAMES):
	    /* The class name array.  */
	    total = 0;
	    for (cnt = 0; cnt < ctype->map_collection_nr; ++cnt, ++offset)
	      {
		iov[2 + elem + offset].iov_base
		  = (void *) ctype->mapnames[cnt];
		iov[2 + elem + offset].iov_len
		  = strlen (ctype->mapnames[cnt]) + 1;
		total += iov[2 + elem + offset].iov_len;
	      }
	    iov[2 + elem + offset].iov_base = (void *) "\0\0\0";
	    iov[2 + elem + offset].iov_len = 1 + (4 - ((total + 1) % 4));
	    total += 1 + (4 - ((total + 1) % 4));

	    idx[elem + 1] = idx[elem] + total;
	    break;

	  CTYPE_DATA (_NL_CTYPE_WIDTH,
		      ctype->width, ctype->plane_size * ctype->plane_cnt);

	  CTYPE_DATA (_NL_CTYPE_MB_CUR_MAX,
		      &ctype->mb_cur_max, sizeof (uint32_t));

	  case _NL_ITEM_INDEX (_NL_CTYPE_CODESET_NAME):
	    total = strlen (ctype->codeset_name) + 1;
	    if (total % 4 == 0)
	      iov[2 + elem + offset].iov_base = (char *) ctype->codeset_name;
	    else
	      {
		iov[2 + elem + offset].iov_base = alloca ((total + 3) & ~3);
		memset (mempcpy (iov[2 + elem + offset].iov_base,
				 ctype->codeset_name, total),
			'\0', 4 - (total & 3));
		total = (total + 3) & ~3;
	      }
	    iov[2 + elem + offset].iov_len = total;
	    idx[elem + 1] = idx[elem] + iov[2 + elem + offset].iov_len;
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_INDIGITS_MB_LEN):
	    iov[2 + elem + offset].iov_base = alloca (sizeof (uint32_t));
	    iov[2 + elem + offset].iov_len = sizeof (uint32_t);
	    *(uint32_t *) iov[2 + elem + offset].iov_base =
	      ctype->mbdigits_act / 10;
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_INDIGITS_WC_LEN):
	    iov[2 + elem + offset].iov_base = alloca (sizeof (uint32_t));
	    iov[2 + elem + offset].iov_len = sizeof (uint32_t);
	    *(uint32_t *) iov[2 + elem + offset].iov_base =
	      ctype->wcdigits_act / 10;
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_INDIGITS0_MB) ... _NL_ITEM_INDEX (_NL_CTYPE_INDIGITS9_MB):
	    /* Compute the length of all possible characters.  For INDIGITS
	       there might be more than one.  We simply concatenate all of
	       them with a NUL byte following.  The NUL byte wouldn't be
	       necessary but it makes it easier for the user.  */
	    total = 0;
	    for (cnt = elem - _NL_CTYPE_INDIGITS0_MB;
		 cnt < ctype->mbdigits_act; cnt += 10)
	      total += ctype->mbdigits[cnt]->nbytes + 1;
	    iov[2 + elem + offset].iov_base = (char *) alloca (total);
	    iov[2 + elem + offset].iov_len = total;

	    cp = iov[2 + elem + offset].iov_base;
	    for (cnt = elem - _NL_CTYPE_INDIGITS0_MB;
		 cnt < ctype->mbdigits_act; cnt += 10)
	      {
		cp = mempcpy (cp, ctype->mbdigits[cnt]->bytes,
			      ctype->mbdigits[cnt]->nbytes);
		*cp++ = '\0';
	      }
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_OUTDIGIT0_MB) ... _NL_ITEM_INDEX (_NL_CTYPE_OUTDIGIT9_MB):
	    /* Compute the length of all possible characters.  For INDIGITS
	       there might be more than one.  We simply concatenate all of
	       them with a NUL byte following.  The NUL byte wouldn't be
	       necessary but it makes it easier for the user.  */
	    cnt = elem - _NL_CTYPE_OUTDIGIT0_MB;
	    total = ctype->mboutdigits[cnt]->nbytes + 1;
	    iov[2 + elem + offset].iov_base = (char *) alloca (total);
	    iov[2 + elem + offset].iov_len = total;

	    *(char *) mempcpy (iov[2 + elem + offset].iov_base,
			       ctype->mbdigits[cnt]->bytes,
			       ctype->mbdigits[cnt]->nbytes) = '\0';
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_INDIGITS0_WC) ... _NL_ITEM_INDEX (_NL_CTYPE_INDIGITS9_WC):
	    total = ctype->wcdigits_act / 10;

	    iov[2 + elem + offset].iov_base =
	      (uint32_t *) alloca (total * sizeof (uint32_t));
	    iov[2 + elem + offset].iov_len = total * sizeof (uint32_t);

	    for (cnt = elem - _NL_CTYPE_INDIGITS0_WC;
		 cnt < ctype->wcdigits_act; cnt += 10)
	      ((uint32_t *) iov[2 + elem + offset].iov_base)[cnt / 10]
		= ctype->wcdigits[cnt];
	    break;

	  case _NL_ITEM_INDEX (_NL_CTYPE_OUTDIGIT0_WC) ... _NL_ITEM_INDEX (_NL_CTYPE_OUTDIGIT9_WC):
	    cnt = elem - _NL_CTYPE_OUTDIGIT0_WC;
	    iov[2 + elem + offset].iov_base = &ctype->wcoutdigits[cnt];
	    iov[2 + elem + offset].iov_len = sizeof (uint32_t);
	    break;

	  default:
	    assert (! "unknown CTYPE element");
	  }
      else
	{
	  /* Handle extra maps.  */
	  size_t nr = (elem - _NL_ITEM_INDEX (_NL_NUM_LC_CTYPE)) >> 1;

	  iov[2 + elem + offset].iov_base = ctype->map[nr];
	  iov[2 + elem + offset].iov_len = ((ctype->plane_size
					     * ctype->plane_cnt + 128)
					    * sizeof (uint32_t));

	  idx[elem + 1] = idx[elem] + iov[2 + elem + offset].iov_len;
	}
    }

  assert (2 + elem + offset == (nelems + ctype->nr_charclass
				+ ctype->map_collection_nr + 2));

  write_locale_data (output_path, "LC_CTYPE", 2 + elem + offset, iov);
}


/* Local functions.  */
static void
ctype_class_new (struct linereader *lr, struct locale_ctype_t *ctype,
		 const char *name)
{
  size_t cnt;

  for (cnt = 0; cnt < ctype->nr_charclass; ++cnt)
    if (strcmp (ctype->classnames[cnt], name) == 0)
      break;

  if (cnt < ctype->nr_charclass)
    {
      lr_error (lr, _("character class `%s' already defined"), name);
      return;
    }

  if (ctype->nr_charclass == MAX_NR_CHARCLASS)
    /* Exit code 2 is prescribed in P1003.2b.  */
    error (2, 0, _("\
implementation limit: no more than %d character classes allowed"),
	   MAX_NR_CHARCLASS);

  ctype->classnames[ctype->nr_charclass++] = name;
}


static void
ctype_map_new (struct linereader *lr, struct locale_ctype_t *ctype,
	       const char *name, struct charmap_t *charmap)
{
  size_t max_chars = 0;
  size_t cnt;

  for (cnt = 0; cnt < ctype->map_collection_nr; ++cnt)
    {
      if (strcmp (ctype->mapnames[cnt], name) == 0)
	break;

      if (max_chars < ctype->map_collection_max[cnt])
	max_chars = ctype->map_collection_max[cnt];
    }

  if (cnt < ctype->map_collection_nr)
    {
      lr_error (lr, _("character map `%s' already defined"), name);
      return;
    }

  if (ctype->map_collection_nr == MAX_NR_CHARMAP)
    /* Exit code 2 is prescribed in P1003.2b.  */
    error (2, 0, _("\
implementation limit: no more than %d character maps allowed"),
	   MAX_NR_CHARMAP);

  ctype->mapnames[cnt] = name;

  if (max_chars == 0)
    ctype->map_collection_max[cnt] = charmap->mb_cur_max == 1 ? 256 : 512;
  else
    ctype->map_collection_max[cnt] = max_chars;

  ctype->map_collection[cnt] = (uint32_t *)
    xmalloc (sizeof (uint32_t) * ctype->map_collection_max[cnt]);
  memset (ctype->map_collection[cnt], '\0',
	  sizeof (uint32_t) * ctype->map_collection_max[cnt]);
  ctype->map_collection_act[cnt] = 256;

  ++ctype->map_collection_nr;
}


/* We have to be prepared that TABLE, MAX, and ACT can be NULL.  This
   is possible if we only want ot extend the name array.  */
static uint32_t *
find_idx (struct locale_ctype_t *ctype, uint32_t **table, size_t *max,
	  size_t *act, uint32_t idx)
{
  size_t cnt;

  if (idx < 256)
    return table == NULL ? NULL : &(*table)[idx];

  for (cnt = 256; cnt < ctype->charnames_act; ++cnt)
    if (ctype->charnames[cnt] == idx)
      break;

  /* We have to distinguish two cases: the name is found or not.  */
  if (cnt == ctype->charnames_act)
    {
      /* Extend the name array.  */
      if (ctype->charnames_act == ctype->charnames_max)
	{
	  ctype->charnames_max *= 2;
	  ctype->charnames = (unsigned int *)
	    xrealloc (ctype->charnames,
		      sizeof (unsigned int) * ctype->charnames_max);
	}
      ctype->charnames[ctype->charnames_act++] = idx;
    }

  if (table == NULL)
    /* We have done everything we are asked to do.  */
    return NULL;

  if (cnt >= *act)
    {
      if (cnt >= *max)
	{
	  size_t old_max = *max;
	  do
	    *max *= 2;
	  while (*max <= cnt);

	  *table =
	    (uint32_t *) xrealloc (*table, *max * sizeof (unsigned long int));
	  memset (&(*table)[old_max], '\0',
		  (*max - old_max) * sizeof (uint32_t));
	}

      *act = cnt;
    }

  return &(*table)[cnt];
}


static int
get_character (struct token *now, struct charmap_t *charmap,
	       struct repertoire_t *repertoire,
	       struct charseq **seqp, uint32_t *wchp)
{
  if (now->tok == tok_bsymbol)
    {
      /* This will hopefully be the normal case.  */
      *wchp = repertoire_find_value (repertoire, now->val.str.startmb,
				     now->val.str.lenmb);
      *seqp = charmap_find_value (charmap, now->val.str.startmb,
				  now->val.str.lenmb);
    }
  else if (now->tok == tok_ucs4)
    {
      *seqp = repertoire_find_seq (repertoire, now->val.ucs4);

      if (*seqp == NULL)
	{
	  /* Compute the value in the charmap from the UCS value.  */
	  const char *symbol = repertoire_find_symbol (repertoire,
						       now->val.ucs4);

	  if (symbol == NULL)
	    *seqp = NULL;
	  else
	    *seqp = charmap_find_value (charmap, symbol, strlen (symbol));

	  if (*seqp == NULL)
	    {
	      /* Insert a negative entry.  */
	      static const struct charseq negative
		= { .ucs4 = ILLEGAL_CHAR_VALUE };
	      uint32_t *newp = obstack_alloc (&repertoire->mem_pool, 4);
	      *newp = now->val.ucs4;

	      insert_entry (&repertoire->seq_table, newp, 4,
			    (void *) &negative);
	    }
	  else
	    (*seqp)->ucs4 = now->val.ucs4;
	}
      else if ((*seqp)->ucs4 != now->val.ucs4)
	*seqp = NULL;

      *wchp = now->val.ucs4;
    }
  else if (now->tok == tok_charcode)
    {
      /* We must map from the byte code to UCS4.  */
      *seqp = charmap_find_symbol (charmap, now->val.str.startmb,
				   now->val.str.lenmb);

      if (*seqp == NULL)
	*wchp = ILLEGAL_CHAR_VALUE;
      else
	{
	  if ((*seqp)->ucs4 == UNINITIALIZED_CHAR_VALUE)
	    (*seqp)->ucs4 = repertoire_find_value (repertoire, (*seqp)->name,
						   strlen ((*seqp)->name));
	  *wchp = (*seqp)->ucs4;
	}
    }
  else
    return 1;

  return 0;
}


/* Ellipsis like in `<foo123>..<foo12a>' or `<j1234>....<j1245>'.  */
static void
charclass_symbolic_ellipsis (struct linereader *ldfile,
			     struct locale_ctype_t *ctype,
			     struct charmap_t *charmap,
			     struct repertoire_t *repertoire,
			     struct token *now,
			     const char *last_str,
			     unsigned long int class256_bit,
			     unsigned long int class_bit, int base,
			     int ignore_content, int handle_digits)
{
  const char *nowstr = now->val.str.startmb;
  char tmp[now->val.str.lenmb + 1];
  const char *cp;
  char *endp;
  unsigned long int from;
  unsigned long int to;

  /* We have to compute the ellipsis values using the symbolic names.  */
  assert (last_str != NULL);

  if (strlen (last_str) != now->val.str.lenmb)
    {
    invalid_range:
      lr_error (ldfile,
		_("`%s' and `%s' are no valid names for symbolic range"),
		last_str, nowstr);
      return;
    }

  if (memcmp (last_str, nowstr, now->val.str.lenmb) == 0)
    /* Nothing to do, the names are the same.  */
    return;

  for (cp = last_str; *cp == *(nowstr + (cp - last_str)); ++cp)
    ;

  errno = 0;
  from = strtoul (cp, &endp, base);
  if ((from == UINT_MAX && errno == ERANGE) || *endp != '\0')
    goto invalid_range;

  to = strtoul (nowstr + (cp - last_str), &endp, base);
  if ((to == UINT_MAX && errno == ERANGE) || *endp != '\0' || from >= to)
    goto invalid_range;

  /* OK, we have a range FROM - TO.  Now we can create the symbolic names.  */
  if (!ignore_content)
    {
      now->val.str.startmb = tmp;
      while (++from <= to)
	{
	  struct charseq *seq;
	  uint32_t wch;

	  sprintf (tmp, (base == 10 ? "%.*s%0*d" : "%.*s%0*X"), cp - last_str,
		   last_str, now->val.str.lenmb - (cp - last_str), from);

	  get_character (now, charmap, repertoire, &seq, &wch);

	  if (seq != NULL && seq->nbytes == 1)
	    /* Yep, we can store information about this byte sequence.  */
	    ctype->class256_collection[seq->bytes[0]] |= class256_bit;

	  if (wch != ILLEGAL_CHAR_VALUE && class_bit != 0)
	    /* We have the UCS4 position.  */
	    *find_idx (ctype, &ctype->class_collection,
		       &ctype->class_collection_max,
		       &ctype->class_collection_act, wch) |= class_bit;

	  if (handle_digits == 1)
	    {
	      /* We must store the digit values.  */
	      if (ctype->mbdigits_act == ctype->mbdigits_max)
		{
		  ctype->mbdigits_max *= 2;
		  ctype->mbdigits = xrealloc (ctype->mbdigits,
					      (ctype->mbdigits_max
					       * sizeof (char *)));
		  ctype->wcdigits_max *= 2;
		  ctype->wcdigits = xrealloc (ctype->wcdigits,
					      (ctype->wcdigits_max
					       * sizeof (uint32_t)));
		}

	      ctype->mbdigits[ctype->mbdigits_act++] = seq;
	      ctype->wcdigits[ctype->wcdigits_act++] = wch;
	    }
	  else if (handle_digits == 2)
	    {
	      /* We must store the digit values.  */
	      if (ctype->outdigits_act >= 10)
		{
		  lr_error (ldfile, _("\
%s: field `%s' does not contain exactly ten entries"),
			    "LC_CTYPE", "outdigit");
		  return;
		}

	      ctype->mboutdigits[ctype->outdigits_act] = seq;
	      ctype->wcoutdigits[ctype->outdigits_act] = wch;
	      ++ctype->outdigits_act;
	    }
	}
    }
}


/* Ellipsis like in `<U1234>..<U2345>'.  */
static void
charclass_ucs4_ellipsis (struct linereader *ldfile,
			 struct locale_ctype_t *ctype,
			 struct charmap_t *charmap,
			 struct repertoire_t *repertoire,
			 struct token *now, uint32_t last_wch,
			 unsigned long int class256_bit,
			 unsigned long int class_bit, int ignore_content,
			 int handle_digits)
{
  if (last_wch > now->val.ucs4)
    {
      lr_error (ldfile, _("\
to-value <U%0*X> of range is smaller than from-value <U%0*X>"),
		(now->val.ucs4 | last_wch) < 65536 ? 4 : 8, now->val.ucs4,
		(now->val.ucs4 | last_wch) < 65536 ? 4 : 8, last_wch);
      return;
    }

  if (!ignore_content)
    while (++last_wch <= now->val.ucs4)
      {
	/* We have to find out whether there is a byte sequence corresponding
	   to this UCS4 value.  */
	struct charseq *seq = repertoire_find_seq (repertoire, last_wch);

	/* If this is the first time we look for this sequence create a new
	   entry.  */
	if (seq == NULL)
	  {
	    /* Find the symbolic name for this UCS4 value.  */
	    const char *symbol = repertoire_find_symbol (repertoire, last_wch);
	    uint32_t *newp = obstack_alloc (&repertoire->mem_pool, 4);
	    *newp = last_wch;

	    if (symbol != NULL)
	      /* We have a name, now search the multibyte value.  */
	      seq = charmap_find_value (charmap, symbol, strlen (symbol));

	    if (seq == NULL)
	      {
		/* We have to create a fake entry.  */
		static const struct charseq negative
		  = { .ucs4 = ILLEGAL_CHAR_VALUE };
		seq = (struct charseq *) &negative;
	      }
	    else
	      seq->ucs4 = last_wch;

	    insert_entry (&repertoire->seq_table, newp, 4, seq);
	  }

	/* We have a name, now search the multibyte value.  */
	if (seq->ucs4 == last_wch && seq->nbytes == 1)
	  /* Yep, we can store information about this byte sequence.  */
	  ctype->class256_collection[(size_t) seq->bytes[0]]
	    |= class256_bit;

	/* And of course we have the UCS4 position.  */
	if (class_bit != 0 && class_bit != 0)
	  *find_idx (ctype, &ctype->class_collection,
		     &ctype->class_collection_max,
		     &ctype->class_collection_act, last_wch) |= class_bit;

	if (handle_digits == 1)
	  {
	    /* We must store the digit values.  */
	    if (ctype->mbdigits_act == ctype->mbdigits_max)
	      {
		ctype->mbdigits_max *= 2;
		ctype->mbdigits = xrealloc (ctype->mbdigits,
					    (ctype->mbdigits_max
					     * sizeof (char *)));
		ctype->wcdigits_max *= 2;
		ctype->wcdigits = xrealloc (ctype->wcdigits,
					    (ctype->wcdigits_max
					     * sizeof (uint32_t)));
	      }

	    ctype->mbdigits[ctype->mbdigits_act++] = (seq->ucs4 == last_wch
						      ? seq : NULL);
	    ctype->wcdigits[ctype->wcdigits_act++] = last_wch;
	  }
	else if (handle_digits == 2)
	  {
	    /* We must store the digit values.  */
	    if (ctype->outdigits_act >= 10)
	      {
		lr_error (ldfile, _("\
%s: field `%s' does not contain exactly ten entries"),
			  "LC_CTYPE", "outdigit");
		return;
	      }

	    ctype->mboutdigits[ctype->outdigits_act] = (seq->ucs4 == last_wch
							? seq : NULL);
	    ctype->wcoutdigits[ctype->outdigits_act] = last_wch;
	    ++ctype->outdigits_act;
	  }
      }
}


/* Ellipsis as in `/xea/x12.../xea/x34'.  */
static void
charclass_charcode_ellipsis (struct linereader *ldfile,
			     struct locale_ctype_t *ctype,
			     struct charmap_t *charmap,
			     struct repertoire_t *repertoire,
			     struct token *now, char *last_charcode,
			     uint32_t last_charcode_len,
			     unsigned long int class256_bit,
			     unsigned long int class_bit, int ignore_content,
			     int handle_digits)
{
  /* First check whether the to-value is larger.  */
  if (now->val.charcode.nbytes != last_charcode_len)
    {
      lr_error (ldfile, _("\
start end end character sequence of range must have the same length"));
      return;
    }

  if (memcmp (last_charcode, now->val.charcode.bytes, last_charcode_len) > 0)
    {
      lr_error (ldfile, _("\
to-value character sequence is smaller than from-value sequence"));
      return;
    }

  if (!ignore_content)
    {
      do
	{
	  /* Increment the byte sequence value.  */
	  struct charseq *seq;
	  uint32_t wch;
	  int i;

	  for (i = last_charcode_len - 1; i >= 0; --i)
	    if (++last_charcode[i] != 0)
	      break;

	  if (last_charcode_len == 1)
	    /* Of course we have the charcode value.  */
	    ctype->class256_collection[(size_t) last_charcode[0]]
	      |= class256_bit;

	  /* Find the symbolic name.  */
	  seq = charmap_find_symbol (charmap, last_charcode,
				     last_charcode_len);
	  if (seq != NULL)
	    {
	      if (seq->ucs4 == UNINITIALIZED_CHAR_VALUE)
		seq->ucs4 = repertoire_find_value (repertoire, seq->name,
						   strlen (seq->name));
	      wch = seq->ucs4;

	      if (wch != ILLEGAL_CHAR_VALUE && class_bit != 0)
		*find_idx (ctype, &ctype->class_collection,
			   &ctype->class_collection_max,
			   &ctype->class_collection_act, wch) |= class_bit;
	    }
	  else
	    wch = ILLEGAL_CHAR_VALUE;

	  if (handle_digits == 1)
	    {
	      /* We must store the digit values.  */
	      if (ctype->mbdigits_act == ctype->mbdigits_max)
		{
		  ctype->mbdigits_max *= 2;
		  ctype->mbdigits = xrealloc (ctype->mbdigits,
					      (ctype->mbdigits_max
					       * sizeof (char *)));
		  ctype->wcdigits_max *= 2;
		  ctype->wcdigits = xrealloc (ctype->wcdigits,
					      (ctype->wcdigits_max
					       * sizeof (uint32_t)));
		}

	      seq = xmalloc (sizeof (struct charseq) + last_charcode_len);
	      memcpy ((char *) (seq + 1), last_charcode, last_charcode_len);
	      seq->nbytes = last_charcode_len;

	      ctype->mbdigits[ctype->mbdigits_act++] = seq;
	      ctype->wcdigits[ctype->wcdigits_act++] = wch;
	    }
	  else if (handle_digits == 2)
	    {
	      struct charseq *seq;
	      /* We must store the digit values.  */
	      if (ctype->outdigits_act >= 10)
		{
		  lr_error (ldfile, _("\
%s: field `%s' does not contain exactly ten entries"),
			    "LC_CTYPE", "outdigit");
		  return;
		}

	      seq = xmalloc (sizeof (struct charseq) + last_charcode_len);
	      memcpy ((char *) (seq + 1), last_charcode, last_charcode_len);
	      seq->nbytes = last_charcode_len;

	      ctype->mboutdigits[ctype->outdigits_act] = seq;
	      ctype->wcoutdigits[ctype->outdigits_act] = wch;
	      ++ctype->outdigits_act;
	    }
	}
      while (memcmp (last_charcode, now->val.charcode.bytes,
		     last_charcode_len) != 0);
    }
}


/* Read one transliteration entry.  */
static uint32_t *
read_widestring (struct linereader *ldfile, struct token *now,
		 struct charmap_t *charmap, struct repertoire_t *repertoire)
{
  uint32_t *wstr;

  if (now->tok == tok_default_missing)
    /* The special name "" will denote this case.  */
    wstr = (uint32_t *) L"";
  else if (now->tok == tok_bsymbol)
    {
      /* Get the value from the repertoire.  */
      wstr = xmalloc (2 * sizeof (uint32_t));
      wstr[0] = repertoire_find_value (repertoire, now->val.str.startmb,
				       now->val.str.lenmb);
      if (wstr[0] == ILLEGAL_CHAR_VALUE)
	/* We cannot proceed, we don't know the UCS4 value.  */
	return NULL;

      wstr[1] = 0;
    }
  else if (now->tok == tok_ucs4)
    {
      wstr = xmalloc (2 * sizeof (uint32_t));
      wstr[0] = now->val.ucs4;
      wstr[1] = 0;
    }
  else if (now->tok == tok_charcode)
    {
      /* Argh, we have to convert to the symbol name first and then to the
	 UCS4 value.  */
      struct charseq *seq = charmap_find_symbol (charmap,
						 now->val.str.startmb,
						 now->val.str.lenmb);
      if (seq == NULL)
	/* Cannot find the UCS4 value.  */
	return NULL;

      if (seq->ucs4 == UNINITIALIZED_CHAR_VALUE)
	seq->ucs4 = repertoire_find_value (repertoire, seq->name,
					   strlen (seq->name));
      if (seq->ucs4 == ILLEGAL_CHAR_VALUE)
	/* We cannot proceed, we don't know the UCS4 value.  */
	return NULL;

      wstr = xmalloc (2 * sizeof (uint32_t));
      wstr[0] = seq->ucs4;
      wstr[1] = 0;
    }
  else if (now->tok == tok_string)
    {
      wstr = now->val.str.startwc;
      if (wstr[0] == 0)
	return NULL;
    }
  else
    {
      if (now->tok != tok_eol && now->tok != tok_eof)
	lr_ignore_rest (ldfile, 0);
      SYNTAX_ERROR (_("%s: syntax error"), "LC_CTYPE");
      return (uint32_t *) -1l;
    }

  return wstr;
}


static void
read_translit_entry (struct linereader *ldfile, struct locale_ctype_t *ctype,
		     struct token *now, struct charmap_t *charmap,
		     struct repertoire_t *repertoire)
{
  uint32_t *from_wstr = read_widestring (ldfile, now, charmap, repertoire);
  struct translit_t *result;
  struct translit_to_t **top;
  struct obstack *ob = &ctype->mem_pool;
  int first;
  int ignore;

  if (from_wstr == NULL)
    /* There is no valid from string.  */
    return;

  result = (struct translit_t *) obstack_alloc (ob,
						sizeof (struct translit_t));
  result->from = from_wstr;
  result->next = NULL;
  result->to = NULL;
  top = &result->to;
  first = 1;
  ignore = 0;

  while (1)
    {
      uint32_t *to_wstr;

      /* Next we have one or more transliterations.  They are
	 separated by semicolons.  */
      now = lr_token (ldfile, charmap, repertoire);

      if (!first && (now->tok == tok_semicolon || now->tok == tok_eol))
	{
	  /* One string read.  */
	  const uint32_t zero = 0;

	  if (!ignore)
	    {
	      obstack_grow (ob, &zero, 4);
	      to_wstr = obstack_finish (ob);

	      *top = obstack_alloc (ob, sizeof (struct translit_to_t));
	      (*top)->str = to_wstr;
	      (*top)->next = NULL;
	    }

	  if (now->tok == tok_eol)
	    {
	      result->next = ctype->translit;
	      ctype->translit = result;
	      return;
	    }

	  if (!ignore)
	    top = &(*top)->next;
	  ignore = 0;
	}
      else
	{
	  to_wstr = read_widestring (ldfile, now, charmap, repertoire);
	  if (to_wstr == (uint32_t *) -1l)
	    {
	      /* An error occurred.  */
	      obstack_free (ob, result);
	      return;
	    }

	  if (to_wstr == NULL)
	    ignore = 1;
	  else
	    /* This value is usable.  */
	    obstack_grow (ob, to_wstr, wcslen ((wchar_t *) to_wstr) * 4);

	  first = 0;
	}
    }
}


/* The parser for the LC_CTYPE section of the locale definition.  */
void
ctype_read (struct linereader *ldfile, struct localedef_t *result,
	    struct charmap_t *charmap, const char *repertoire_name,
	    int ignore_content)
{
  struct repertoire_t *repertoire = NULL;
  struct locale_ctype_t *ctype;
  struct token *now;
  enum token_t nowtok;
  size_t cnt;
  struct charseq *last_seq;
  uint32_t last_wch = 0;
  enum token_t last_token;
  enum token_t ellipsis_token;
  char last_charcode[16];
  size_t last_charcode_len = 0;
  const char *last_str = NULL;
  int mapidx;

  /* Get the repertoire we have to use.  */
  if (repertoire_name != NULL)
    repertoire = repertoire_read (repertoire_name);

  /* The rest of the line containing `LC_CTYPE' must be free.  */
  lr_ignore_rest (ldfile, 1);


  do
    {
      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }
  while (nowtok == tok_eol);

  /* If we see `copy' now we are almost done.  */
  if (nowtok == tok_copy)
    {
      handle_copy (ldfile, charmap, repertoire, result, tok_lc_ctype, LC_CTYPE,
		   "LC_CTYPE", ignore_content);
      return;
    }

  /* Prepare the data structures.  */
  ctype_startup (ldfile, result, charmap, ignore_content);
  ctype = result->categories[LC_CTYPE].ctype;

  /* Remember the repertoire we use.  */
  if (!ignore_content)
    ctype->repertoire = repertoire;

  while (1)
    {
      unsigned long int class_bit = 0;
      unsigned long int class256_bit = 0;
      int handle_digits = 0;

      /* Of course we don't proceed beyond the end of file.  */
      if (nowtok == tok_eof)
	break;

      /* Ingore empty lines.  */
      if (nowtok == tok_eol)
	{
	  now = lr_token (ldfile, charmap, NULL);
	  nowtok = now->tok;
	  continue;
	}

      switch (nowtok)
	{
	case tok_class:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  /* We simply forget the `class' keyword and use the following
	     operand to determine the bit.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok == tok_ident || now->tok == tok_string)
	    {
	      /* Must be one of the predefined class names.  */
	      for (cnt = 0; cnt < ctype->nr_charclass; ++cnt)
		if (strcmp (ctype->classnames[cnt], now->val.str.startmb) == 0)
		  break;
	      if (cnt >= ctype->nr_charclass)
		{
		  if (now->val.str.lenmb == 8
		      && memcmp ("special1", now->val.str.startmb, 8) == 0)
		    class_bit = _ISwspecial1;
		  else if (now->val.str.lenmb == 8
		      && memcmp ("special2", now->val.str.startmb, 8) == 0)
		    class_bit = _ISwspecial2;
		  else if (now->val.str.lenmb == 8
		      && memcmp ("special3", now->val.str.startmb, 8) == 0)
		    class_bit = _ISwspecial3;
		  else
		    {
		      lr_error (ldfile, _("\
unknown character class `%s' in category `LC_CTYPE'"),
				now->val.str.startmb);
		      free (now->val.str.startmb);

		      lr_ignore_rest (ldfile, 0);
		      continue;
		    }
		}
	      else
		class_bit = _ISwbit (cnt);

	      free (now->val.str.startmb);
	    }
	  else if (now->tok == tok_digit)
	    goto handle_tok_digit;
	  else if (now->tok < tok_upper || now->tok > tok_blank)
	    goto err_label;
	  else
	    {
	      class_bit = BITw (now->tok);
	      class256_bit = BIT (now->tok);
	    }

	  /* The next character must be a semicolon.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok != tok_semicolon)
	    goto err_label;
	  goto read_charclass;

	case tok_upper:
	case tok_lower:
	case tok_alpha:
	case tok_alnum:
	case tok_space:
	case tok_cntrl:
	case tok_punct:
	case tok_graph:
	case tok_print:
	case tok_xdigit:
	case tok_blank:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  class_bit = BITw (now->tok);
	  class256_bit = BIT (now->tok);
	  handle_digits = 0;
	read_charclass:
	  ctype->class_done |= class_bit;
	  last_token = tok_none;
	  ellipsis_token = tok_none;
	  now = lr_token (ldfile, charmap, NULL);
	  while (now->tok != tok_eol && now->tok != tok_eof)
	    {
	      uint32_t wch;
	      struct charseq *seq;

	      if (ellipsis_token == tok_none)
		{
		  if (get_character (now, charmap, repertoire, &seq, &wch))
		    goto err_label;

		  if (!ignore_content && seq != NULL && seq->nbytes == 1)
		    /* Yep, we can store information about this byte
		       sequence.  */
		    ctype->class256_collection[seq->bytes[0]] |= class256_bit;

		  if (!ignore_content && wch != ILLEGAL_CHAR_VALUE
		      && class_bit != 0)
		    /* We have the UCS4 position.  */
		    *find_idx (ctype, &ctype->class_collection,
			       &ctype->class_collection_max,
			       &ctype->class_collection_act, wch) |= class_bit;

		  last_token = now->tok;
		  last_str = now->val.str.startmb;
		  last_seq = seq;
		  last_wch = wch;
		  memcpy (last_charcode, now->val.charcode.bytes, 16);
		  last_charcode_len = now->val.charcode.nbytes;

		  if (!ignore_content && handle_digits == 1)
		    {
		      /* We must store the digit values.  */
		      if (ctype->mbdigits_act == ctype->mbdigits_max)
			{
			  ctype->mbdigits_max += 10;
			  ctype->mbdigits = xrealloc (ctype->mbdigits,
						      (ctype->mbdigits_max
						       * sizeof (char *)));
			  ctype->wcdigits_max += 10;
			  ctype->wcdigits = xrealloc (ctype->wcdigits,
						      (ctype->wcdigits_max
						       * sizeof (uint32_t)));
			}

		      ctype->mbdigits[ctype->mbdigits_act++] = seq;
		      ctype->wcdigits[ctype->wcdigits_act++] = wch;
		    }
		  else if (!ignore_content && handle_digits == 2)
		    {
		      /* We must store the digit values.  */
		      if (ctype->outdigits_act >= 10)
			{
			  lr_error (ldfile, _("\
%s: field `%s' does not contain exactly ten entries"),
			    "LC_CTYPE", "outdigit");
			  goto err_label;
			}

		      ctype->mboutdigits[ctype->outdigits_act] = seq;
		      ctype->wcoutdigits[ctype->outdigits_act] = wch;
		      ++ctype->outdigits_act;
		    }
		}
	      else
		{
		  /* Now it gets complicated.  We have to resolve the
		     ellipsis problem.  First we must distinguish between
		     the different kind of ellipsis and this must match the
		     tokens we have seen.  */
		  assert (last_token != tok_none);

		  if (last_token != now->tok)
		    {
		      lr_error (ldfile, _("\
ellipsis range must be marked by two operands of same type"));
		      lr_ignore_rest (ldfile, 0);
		      break;
		    }

		  if (last_token == tok_bsymbol)
		    {
		      if (ellipsis_token == tok_ellipsis3)
			lr_error (ldfile, _("with symbolic name range values \
the absolute ellipsis `...' must not be used"));

		      charclass_symbolic_ellipsis (ldfile, ctype, charmap,
						   repertoire, now, last_str,
						   class256_bit, class_bit,
						   (ellipsis_token
						    == tok_ellipsis4
						    ? 10 : 16),
						   ignore_content,
						   handle_digits);
		    }
		  else if (last_token == tok_ucs4)
		    {
		      if (ellipsis_token != tok_ellipsis2)
			lr_error (ldfile, _("\
with UCS range values one must use the hexadecimal symbolic ellipsis `..'"));

		      charclass_ucs4_ellipsis (ldfile, ctype, charmap,
					       repertoire, now, last_wch,
					       class256_bit, class_bit,
					       ignore_content, handle_digits);
		    }
		  else
		    {
		      assert (last_token == tok_charcode);

		      if (ellipsis_token != tok_ellipsis3)
			lr_error (ldfile, _("\
with character code range values one must use the absolute ellipsis `...'"));

		      charclass_charcode_ellipsis (ldfile, ctype, charmap,
						   repertoire, now,
						   last_charcode,
						   last_charcode_len,
						   class256_bit, class_bit,
						   ignore_content,
						   handle_digits);
		    }

		  /* Now we have used the last value.  */
		  last_token = tok_none;
		}

	      /* Next we expect a semicolon or the end of the line.  */
	      now = lr_token (ldfile, charmap, NULL);
	      if (now->tok == tok_eol || now->tok == tok_eof)
		break;

	      if (last_token != tok_none
		  && now->tok >= tok_ellipsis2 && now->tok <= tok_ellipsis4)
		{
		  ellipsis_token = now->tok;
		  now = lr_token (ldfile, charmap, NULL);
		  continue;
		}

	      if (now->tok != tok_semicolon)
		goto err_label;

	      /* And get the next character.  */
	      now = lr_token (ldfile, charmap, NULL);

	      ellipsis_token = tok_none;
	    }
	  break;

	case tok_digit:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    break;

	handle_tok_digit:
	  class_bit = _ISwdigit;
	  class256_bit = _ISdigit;
	  handle_digits = 1;
	  goto read_charclass;

	case tok_outdigit:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (ctype->outdigits_act != 0)
	    lr_error (ldfile, _("\
%s: field `%s' declared more than once"),
		      "LC_CTYPE", "outdigit");
	  class_bit = 0;
	  class256_bit = 0;
	  handle_digits = 2;
	  goto read_charclass;

	case tok_toupper:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  mapidx = 0;
	  goto read_mapping;

	case tok_tolower:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  mapidx = 1;
	  goto read_mapping;

	case tok_map:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  /* We simply forget the `map' keyword and use the following
	     operand to determine the mapping.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok == tok_ident || now->tok == tok_string)
	    {
	      size_t cnt;

	      for (cnt = 2; cnt < ctype->map_collection_nr; ++cnt)
		if (strcmp (now->val.str.startmb, ctype->mapnames[cnt]) == 0)
		  break;

	      if (cnt < ctype->map_collection_nr)
		mapidx = cnt;
	      else
		{
		  lr_error (ldfile, _("unknown map `%s'"),
			    now->val.str.startmb);
		  lr_ignore_rest (ldfile, 0);
		  break;
		}
	    }
	  else if (now->tok < tok_toupper || now->tok > tok_tolower)
	    goto err_label;
	  else
	    mapidx = now->tok - tok_toupper;

	  now = lr_token (ldfile, charmap, NULL);
	  /* This better should be a semicolon.  */
	  if (now->tok != tok_semicolon)
	    goto err_label;

	read_mapping:
	  /* Test whether this mapping was already defined.  */
	  if (ctype->tomap_done[mapidx])
	    {
	      lr_error (ldfile, _("duplicated definition for mapping `%s'"),
			ctype->mapnames[mapidx]);
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }
	  ctype->tomap_done[mapidx] = 1;

	  now = lr_token (ldfile, charmap, NULL);
	  while (now->tok != tok_eol && now->tok != tok_eof)
	    {
	      struct charseq *from_seq;
	      uint32_t from_wch;
	      struct charseq *to_seq;
	      uint32_t to_wch;

	      /* Every pair starts with an opening brace.  */
	      if (now->tok != tok_open_brace)
		goto err_label;

	      /* Next comes the from-value.  */
	      now = lr_token (ldfile, charmap, NULL);
	      if (get_character (now, charmap, repertoire, &from_seq,
				 &from_wch) != 0)
		goto err_label;

	      /* The next is a comma.  */
	      now = lr_token (ldfile, charmap, NULL);
	      if (now->tok != tok_comma)
		goto err_label;

	      /* And the other value.  */
	      now = lr_token (ldfile, charmap, NULL);
	      if (get_character (now, charmap, repertoire, &to_seq,
				 &to_wch) != 0)
		goto err_label;

	      /* And the last thing is the closing brace.  */
	      now = lr_token (ldfile, charmap, NULL);
	      if (now->tok != tok_close_brace)
		goto err_label;

	      if (!ignore_content)
		{
		  if (mapidx < 2 && from_seq != NULL && to_seq != NULL
		      && from_seq->nbytes == 1 && to_seq->nbytes == 1)
		    /* We can use this value.  */
		    ctype->map256_collection[mapidx][from_seq->bytes[0]]
		      = to_seq->bytes[0];

		  if (from_wch != ILLEGAL_CHAR_VALUE
		      && to_wch != ILLEGAL_CHAR_VALUE)
		    /* Both correct values.  */
		    *find_idx (ctype, &ctype->map_collection[mapidx],
			       &ctype->map_collection_max[mapidx],
			       &ctype->map_collection_act[mapidx],
			       from_wch) = to_wch;
		}

	      /* Now comes a semicolon or the end of the line/file.  */
	      now = lr_token (ldfile, charmap, NULL);
	      if (now->tok == tok_semicolon)
		now = lr_token (ldfile, charmap, NULL);
	    }
	  break;

	case tok_translit_start:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  /* The rest of the line better should be empty.  */
	  lr_ignore_rest (ldfile, 1);

	  /* We count here the number of allocated entries in the `translit'
	     array.  */
	  cnt = 0;

	  /* We proceed until we see the `translit_end' token.  */
	  while (now = lr_token (ldfile, charmap, repertoire),
		 now->tok != tok_translit_end && now->tok != tok_eof)
	    {
	      if (now->tok == tok_eol)
		/* Ignore empty lines.  */
		continue;

	      if (now->tok == tok_translit_end)
		{
		  lr_ignore_rest (ldfile, 0);
		  break;
		}

	      if (now->tok == tok_include)
		{
		  /* We have to include locale.  */
		  const char *locale_name;
		  const char *repertoire_name;

		  now = lr_token (ldfile, charmap, NULL);
		  /* This should be a string or an identifier.  In any
		     case something to name a locale.  */
		  if (now->tok != tok_string && now->tok != tok_ident)
		    {
		    translit_syntax:
		      lr_error (ldfile, _("%s: syntax error"), "LC_CTYPE");
		      lr_ignore_rest (ldfile, 0);
		      continue;
		    }
		  locale_name = now->val.str.startmb;

		  /* Next should be a semicolon.  */
		  now = lr_token (ldfile, charmap, NULL);
		  if (now->tok != tok_semicolon)
		    goto translit_syntax;

		  /* Now the repertoire name.  */
		  now = lr_token (ldfile, charmap, NULL);
		  if ((now->tok != tok_string && now->tok != tok_ident)
		      || now->val.str.startmb == NULL)
		    goto translit_syntax;
		  repertoire_name = now->val.str.startmb;

		  /* We must not have more than one `include'.  */
		  if (ctype->translit_copy_locale != NULL)
		    {
		      lr_error (ldfile, _("\
%s: only one `include' instruction allowed"), "LC_CTYPE");
		      lr_ignore_rest (ldfile, 0);
		      continue;
		    }

		  ctype->translit_copy_locale = locale_name;
		  ctype->translit_copy_repertoire = repertoire_name;

		  /* The rest of the line must be empty.  */
		  lr_ignore_rest (ldfile, 1);
		  continue;
		}

	      read_translit_entry (ldfile, ctype, now, charmap, repertoire);
	    }
	  break;

	case tok_ident:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  /* This could mean one of several things.  First test whether
	     it's a character class name.  */
	  for (cnt = 0; cnt < ctype->nr_charclass; ++cnt)
	    if (strcmp (now->val.str.startmb, ctype->classnames[cnt]) == 0)
	      break;
	  if (cnt < ctype->nr_charclass)
	    {
	      class_bit = _ISwbit (cnt);
	      class256_bit = cnt <= 11 ? _ISbit (cnt) : 0;
	      free (now->val.str.startmb);
	      goto read_charclass;
	    }
	  if (strcmp (now->val.str.startmb, "special1") == 0)
	    {
	      class_bit = _ISwspecial1;
	      free (now->val.str.startmb);
	      goto read_charclass;
	    }
	  if (strcmp (now->val.str.startmb, "special2") == 0)
	    {
	      class_bit = _ISwspecial2;
	      free (now->val.str.startmb);
	      goto read_charclass;
	    }
	  if (strcmp (now->val.str.startmb, "special3") == 0)
	    {
	      class_bit = _ISwspecial3;
	      free (now->val.str.startmb);
	      goto read_charclass;
	    }
	  if (strcmp (now->val.str.startmb, "tosymmetric") == 0)
	    {
	      mapidx = 2;
	      goto read_mapping;
	    }
	  break;

	case tok_end:
	  /* Next we assume `LC_CTYPE'.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok == tok_eof)
	    break;
	  if (now->tok == tok_eol)
	    lr_error (ldfile, _("%s: incomplete `END' line"),
		      "LC_CTYPE");
	  else if (now->tok != tok_lc_ctype)
	    lr_error (ldfile, _("\
%1$s: definition does not end with `END %1$s'"), "LC_CTYPE");
	  lr_ignore_rest (ldfile, now->tok == tok_lc_ctype);
	  return;

	default:
	err_label:
	  if (now->tok != tok_eof)
	    SYNTAX_ERROR (_("%s: syntax error"), "LC_CTYPE");
	}

      /* Prepare for the next round.  */
      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }

  /* When we come here we reached the end of the file.  */
  lr_error (ldfile, _("%s: premature end of file"), "LC_CTYPE");
}


static void
set_class_defaults (struct locale_ctype_t *ctype, struct charmap_t *charmap,
		    struct repertoire_t *repertoire)
{
  size_t cnt;

  /* These function defines the default values for the classes and conversions
     according to POSIX.2 2.5.2.1.
     It may seem that the order of these if-blocks is arbitrary but it is NOT.
     Don't move them unless you know what you do!  */

  void set_default (int bitpos, int from, int to)
    {
      char tmp[2];
      int ch;
      int bit = _ISbit (bitpos);
      int bitw = _ISwbit (bitpos);
      /* Define string.  */
      strcpy (tmp, "?");

      for (ch = from; ch <= to; ++ch)
	{
	  uint32_t value;
	  struct charseq *seq;
	  tmp[0] = ch;

	  value = repertoire_find_value (repertoire, tmp, 1);
	  if (value == ILLEGAL_CHAR_VALUE)
	    {
	      if (!be_quiet)
		error (0, 0, _("\
%s: character `%s' not defined in repertoire while needed as default value"),
		       "LC_CTYPE", tmp);
	    }
	  else
	    ELEM (ctype, class_collection, , value) |= bitw;

	  seq = charmap_find_value (charmap, tmp, 1);
	  if (seq == NULL)
	    {
	      if (!be_quiet)
		error (0, 0, _("\
%s: character `%s' not defined in charmap while needed as default value"),
		       "LC_CTYPE", tmp);
	    }
	  else if (seq->nbytes != 1)
	    error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
		   "LC_CTYPE", tmp);
	  else
	    ctype->class256_collection[seq->bytes[0]] |= bit;
	}
    }

  /* Set default values if keyword was not present.  */
  if ((ctype->class_done & BITw (tok_upper)) == 0)
    /* "If this keyword [lower] is not specified, the lowercase letters
        `A' through `Z', ..., shall automatically belong to this class,
	with implementation defined character values."  [P1003.2, 2.5.2.1]  */
    set_default (BITPOS (tok_upper), 'A', 'Z');

  if ((ctype->class_done & BITw (tok_lower)) == 0)
    /* "If this keyword [lower] is not specified, the lowercase letters
        `a' through `z', ..., shall automatically belong to this class,
	with implementation defined character values."  [P1003.2, 2.5.2.1]  */
    set_default (BITPOS (tok_lower), 'a', 'z');

  if ((ctype->class_done & BITw (tok_alpha)) == 0)
    {
      /* Table 2-6 in P1003.2 says that characters in class `upper' or
	 class `lower' *must* be in class `alpha'.  */
      unsigned long int mask = BIT (tok_upper) | BIT (tok_lower);

      for (cnt = 0; cnt < ctype->class_collection_act; ++cnt)
	if ((ctype->class_collection[cnt] & mask) != 0)
	  ctype->class_collection[cnt] |= BIT (tok_alpha);
    }

  if ((ctype->class_done & BITw (tok_digit)) == 0)
    /* "If this keyword [digit] is not specified, the digits `0' through
        `9', ..., shall automatically belong to this class, with
	implementation-defined character values."  [P1003.2, 2.5.2.1]  */
    set_default (BITPOS (tok_digit), '0', '9');

  /* "Only characters specified for the `alpha' and `digit' keyword
     shall be specified.  Characters specified for the keyword `alpha'
     and `digit' are automatically included in this class.  */
  {
    unsigned long int mask = BIT (tok_alpha) | BIT (tok_digit);

    for (cnt = 0; cnt < ctype->class_collection_act; ++cnt)
      if ((ctype->class_collection[cnt] & mask) != 0)
	ctype->class_collection[cnt] |= BIT (tok_alnum);
  }

  if ((ctype->class_done & BITw (tok_space)) == 0)
    /* "If this keyword [space] is not specified, the characters <space>,
        <form-feed>, <newline>, <carriage-return>, <tab>, and
	<vertical-tab>, ..., shall automatically belong to this class,
	with implementation-defined character values."  [P1003.2, 2.5.2.1]  */
    {
      uint32_t value;
      struct charseq *seq;

      value = repertoire_find_value (repertoire, "space", 5);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<space>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_space);

      seq = charmap_find_value (charmap, "space", 5);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<space>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<space>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_space);


      value = repertoire_find_value (repertoire, "form-feed", 9);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<form-feed>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_space);

      seq = charmap_find_value (charmap, "form-feed", 9);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<form-feed>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<form-feed>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_space);


      value = repertoire_find_value (repertoire, "newline", 7);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<newline>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_space);

      seq = charmap_find_value (charmap, "newline", 7);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
character `%s' not defined while needed as default value"),
		   "<newline>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<newline>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_space);


      value = repertoire_find_value (repertoire, "carriage-return", 15);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<carriage-return>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_space);

      seq = charmap_find_value (charmap, "carriage-return", 15);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<carriage-return>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<carriage-return>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_space);


      value = repertoire_find_value (repertoire, "tab", 3);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<tab>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_space);

      seq = charmap_find_value (charmap, "tab", 3);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<tab>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<tab>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_space);


      value = repertoire_find_value (repertoire, "vertical-tab", 12);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<vertical-tab>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_space);

      seq = charmap_find_value (charmap, "vertical-tab", 12);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<vertical-tab>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<vertical-tab>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_space);
    }

  if ((ctype->class_done & BITw (tok_xdigit)) == 0)
    /* "If this keyword is not specified, the digits `0' to `9', the
        uppercase letters `A' through `F', and the lowercase letters `a'
	through `f', ..., shell automatically belong to this class, with
	implementation defined character values."  [P1003.2, 2.5.2.1]  */
    {
      set_default (BITPOS (tok_xdigit), '0', '9');
      set_default (BITPOS (tok_xdigit), 'A', 'F');
      set_default (BITPOS (tok_xdigit), 'a', 'f');
    }

  if ((ctype->class_done & BITw (tok_blank)) == 0)
    /* "If this keyword [blank] is unspecified, the characters <space> and
       <tab> shall belong to this character class."  [P1003.2, 2.5.2.1]  */
   {
      uint32_t value;
      struct charseq *seq;

      value = repertoire_find_value (repertoire, "space", 5);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<space>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_blank);

      seq = charmap_find_value (charmap, "space", 5);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<space>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<space>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_blank);


      value = repertoire_find_value (repertoire, "tab", 3);
      if (value == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<tab>");
	}
      else
	ELEM (ctype, class_collection, , value) |= BIT (tok_blank);

      seq = charmap_find_value (charmap, "tab", 3);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<tab>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<tab>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_blank);
    }

  if ((ctype->class_done & BITw (tok_graph)) == 0)
    /* "If this keyword [graph] is not specified, characters specified for
        the keywords `upper', `lower', `alpha', `digit', `xdigit' and `punct',
	shall belong to this character class."  [P1003.2, 2.5.2.1]  */
    {
      unsigned long int mask = BIT (tok_upper) | BIT (tok_lower) |
	BIT (tok_alpha) | BIT (tok_digit) | BIT (tok_xdigit) | BIT (tok_punct);
      size_t cnt;

      for (cnt = 0; cnt < ctype->class_collection_act; ++cnt)
	if ((ctype->class_collection[cnt] & mask) != 0)
	  ctype->class_collection[cnt] |= BIT (tok_graph);

      for (cnt = 0; cnt < 256; ++cnt)
	if ((ctype->class256_collection[cnt] & mask) != 0)
	  ctype->class256_collection[cnt] |= BIT (tok_graph);
    }

  if ((ctype->class_done & BITw (tok_print)) == 0)
    /* "If this keyword [print] is not provided, characters specified for
        the keywords `upper', `lower', `alpha', `digit', `xdigit', `punct',
	and the <space> character shall belong to this character class."
	[P1003.2, 2.5.2.1]  */
    {
      unsigned long int mask = BIT (tok_upper) | BIT (tok_lower) |
	BIT (tok_alpha) | BIT (tok_digit) | BIT (tok_xdigit) | BIT (tok_punct);
      size_t cnt;
      uint32_t space;
      struct charseq *seq;

      for (cnt = 0; cnt < ctype->class_collection_act; ++cnt)
	if ((ctype->class_collection[cnt] & mask) != 0)
	  ctype->class_collection[cnt] |= BIT (tok_print);

      for (cnt = 0; cnt < 256; ++cnt)
	if ((ctype->class256_collection[cnt] & mask) != 0)
	  ctype->class256_collection[cnt] |= BIT (tok_print);


      space = repertoire_find_value (repertoire, "space", 5);
      if (space == ILLEGAL_CHAR_VALUE)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<space>");
	}
      else
	ELEM (ctype, class_collection, , space) |= BIT (tok_print);

      seq = charmap_find_value (charmap, "space", 5);
      if (seq == NULL)
	{
	  if (!be_quiet)
	    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		   "LC_CTYPE", "<space>");
	}
      else if (seq->nbytes != 1)
	error (0, 0, _("\
%s: character `%s' in charmap not representable with one byte"),
	       "LC_CTYPE", "<space>");
      else
	ctype->class256_collection[seq->bytes[0]] |= BIT (tok_print);
    }

  if (ctype->tomap_done[0] == 0)
    /* "If this keyword [toupper] is not specified, the lowercase letters
        `a' through `z', and their corresponding uppercase letters `A' to
	`Z', ..., shall automatically be included, with implementation-
	defined character values."  [P1003.2, 2.5.2.1]  */
    {
      char tmp[4];
      int ch;

      strcpy (tmp, "<?>");

      for (ch = 'a'; ch <= 'z'; ++ch)
	{
	  uint32_t value_from, value_to;
	  struct charseq *seq_from, *seq_to;

	  tmp[1] = (char) ch;

	  value_from = repertoire_find_value (repertoire, &tmp[1], 1);
	  if (value_from == ILLEGAL_CHAR_VALUE)
	    {
	      if (!be_quiet)
		error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		       "LC_CTYPE", tmp);
	    }
	  else
	    {
	      /* This conversion is implementation defined.  */
	      tmp[1] = (char) (ch + ('A' - 'a'));
	      value_to = repertoire_find_value (repertoire, &tmp[1], 1);
	      if (value_to == ILLEGAL_CHAR_VALUE)
		{
		  if (!be_quiet)
		    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
			   "LC_CTYPE", tmp);
		}
	      else
		/* The index [0] is determined by the order of the
		   `ctype_map_newP' calls in `ctype_startup'.  */
		ELEM (ctype, map_collection, [0], value_from) = value_to;
	    }

	  seq_from = charmap_find_value (charmap, &tmp[1], 1);
	  if (seq_from == NULL)
	    {
	      if (!be_quiet)
		error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
		       "LC_CTYPE", tmp);
	    }
	  else if (seq_from->nbytes != 1)
	    {
	      if (!be_quiet)
		error (0, 0, _("\
%s: character `%s' needed as default value not representable with one byte"),
		       "LC_CTYPE", tmp);
	    }
	  else
	    {
	      /* This conversion is implementation defined.  */
	      tmp[1] = (char) (ch + ('A' - 'a'));
	      seq_to = charmap_find_value (charmap, &tmp[1], 1);
	      if (seq_to == NULL)
		{
		  if (!be_quiet)
		    error (0, 0, _("\
%s: character `%s' not defined while needed as default value"),
			   "LC_CTYPE", tmp);
		}
	      else if (seq_to->nbytes != 1)
		{
		  if (!be_quiet)
		    error (0, 0, _("\
%s: character `%s' needed as default value not representable with one byte"),
			   "LC_CTYPE", tmp);
		}
	      else
		/* The index [0] is determined by the order of the
		   `ctype_map_newP' calls in `ctype_startup'.  */
		ctype->map256_collection[0][seq_from->bytes[0]]
		  = seq_to->bytes[0];
	    }
	}
    }

  if (ctype->tomap_done[1] == 0)
    /* "If this keyword [tolower] is not specified, the mapping shall be
       the reverse mapping of the one specified to `toupper'."  [P1003.2]  */
    {
      for (cnt = 0; cnt < ctype->map_collection_act[0]; ++cnt)
	if (ctype->map_collection[0][cnt] != 0)
	  ELEM (ctype, map_collection, [1],
		ctype->map_collection[0][cnt])
	    = ctype->charnames[cnt];

      for (cnt = 0; cnt < 256; ++cnt)
	if (ctype->map256_collection[0][cnt] != 0)
	  ctype->map_collection[1][ctype->map_collection[0][cnt]]
	    = ctype->charnames[cnt];
    }

  if (ctype->outdigits_act == 0)
    {
      for (cnt = 0; cnt < 10; ++cnt)
	{
	  ctype->mboutdigits[cnt] = charmap_find_symbol (charmap,
							 digits + cnt, 1);

	  if (ctype->mboutdigits[cnt] == NULL)
	    {
	      ctype->mboutdigits[cnt] = charmap_find_symbol (charmap,
							     longnames[cnt],
							     strlen (longnames[cnt]));

	      if (ctype->mboutdigits[cnt] == NULL)
		{
		  /* Provide a replacement.  */
		  error (0, 0, _("\
no output digits defined and none of the standard names in the charmap"));

		  ctype->mboutdigits[cnt] = obstack_alloc (&charmap->mem_pool,
							   sizeof (struct charseq) + 1);

		  /* This is better than nothing.  */
		  ctype->mboutdigits[cnt]->bytes[0] = digits[cnt];
		  ctype->mboutdigits[cnt]->nbytes = 1;
		}
	    }

	  ctype->wcoutdigits[cnt] = repertoire_find_value (repertoire,
							   digits + cnt, 1);

	  if (ctype->wcoutdigits[cnt] == ILLEGAL_CHAR_VALUE)
	    {
	      ctype->wcoutdigits[cnt] = repertoire_find_value (repertoire,
							       longnames[cnt],
							       strlen (longnames[cnt]));

	      if (ctype->wcoutdigits[cnt] == ILLEGAL_CHAR_VALUE)
		{
		  /* Provide a replacement.  */
		  error (0, 0, _("\
no output digits defined and none of the standard names in the repertoire"));

		  /* This is better than nothing.  */
		  ctype->wcoutdigits[cnt] = (uint32_t) digits[cnt];
		}
	    }
	}

      ctype->outdigits_act = 10;
    }
}


static void
allocate_arrays (struct locale_ctype_t *ctype, struct charmap_t *charmap,
		 struct repertoire_t *repertoire)
{
  size_t idx;

  /* First we have to decide how we organize the arrays.  It is easy
     for a one-byte character set.  But multi-byte character set
     cannot be stored flat because the chars might be sparsely used.
     So we determine an optimal hashing function for the used
     characters.

     We use a very trivial hashing function to store the sparse
     table.  CH % TABSIZE is used as an index.  To solve multiple hits
     we have N planes.  This guarantees a fixed search time for a
     character [N / 2].  In the following code we determine the minmum
     value for TABSIZE * N, where TABSIZE >= 256.  */
  size_t min_total = UINT_MAX;
  size_t act_size = 256;

  if (!be_quiet)
    fputs (_("\
Computing table size for character classes might take a while..."),
	   stderr);

  while (act_size < min_total)
    {
      size_t cnt[act_size];
      size_t act_planes = 1;

      memset (cnt, '\0', sizeof cnt);

      for (idx = 0; idx < 256; ++idx)
	cnt[idx] = 1;

      for (idx = 0; idx < ctype->charnames_act; ++idx)
	if (ctype->charnames[idx] >= 256)
	  {
	    size_t nr = ctype->charnames[idx] % act_size;

	    if (++cnt[nr] > act_planes)
	      {
		act_planes = cnt[nr];
		if (act_size * act_planes >= min_total)
		  break;
	      }
	  }

      if (act_size * act_planes < min_total)
	{
	  min_total = act_size * act_planes;
	  ctype->plane_size = act_size;
	  ctype->plane_cnt = act_planes;
	}

      ++act_size;
    }

  if (!be_quiet)
    fputs (_(" done\n"), stderr);


  ctype->names = (uint32_t *) xcalloc (ctype->plane_size
				       * ctype->plane_cnt,
				       sizeof (uint32_t));

  for (idx = 1; idx < 256; ++idx)
    ctype->names[idx] = idx;

  /* Trick: change the 0th entry's name to 1 to mark the cell occupied.  */
  ctype->names[0] = 1;

  for (idx = 256; idx < ctype->charnames_act; ++idx)
    {
      size_t nr = (ctype->charnames[idx] % ctype->plane_size);
      size_t depth = 0;

      while (ctype->names[nr + depth * ctype->plane_size])
	++depth;
      assert (depth < ctype->plane_cnt);

      ctype->names[nr + depth * ctype->plane_size] = ctype->charnames[idx];

      /* Now for faster access remember the index in the NAMES_B array.  */
      ctype->charnames[idx] = nr + depth * ctype->plane_size;
    }
  ctype->names[0] = 0;


  /* You wonder about this amount of memory?  This is only because some
     users do not manage to address the array with unsigned values or
     data types with range >= 256.  '\200' would result in the array
     index -128.  To help these poor people we duplicate the entries for
     128 up to 255 below the entry for \0.  */
  ctype->ctype_b = (char_class_t *) xcalloc (256 + 128,
					     sizeof (char_class_t));
  ctype->ctype32_b = (char_class32_t *) xcalloc (ctype->plane_size
						 * ctype->plane_cnt,
						 sizeof (char_class32_t));

  /* This is the array accessed using the multibyte string elements.  */
  for (idx = 0; idx < 256; ++idx)
    ctype->ctype_b[128 + idx] = ctype->class256_collection[idx];

  /* Mirror first 127 entries.  We must take care that entry -1 is not
     mirrored because EOF == -1.  */
  for (idx = 0; idx < 127; ++idx)
    ctype->ctype_b[idx] = ctype->ctype_b[256 + idx];

  /* The 32 bit array contains all characters.  */
  for (idx = 0; idx < ctype->class_collection_act; ++idx)
    ctype->ctype32_b[ctype->charnames[idx]] = ctype->class_collection[idx];

  /* Room for table of mappings.  */
  ctype->map = (uint32_t **) xmalloc (ctype->map_collection_nr
				      * sizeof (uint32_t *));

  /* Fill in all mappings.  */
  for (idx = 0; idx < ctype->map_collection_nr; ++idx)
    {
      unsigned int idx2;

      /* Allocate table.  */
      ctype->map[idx] = (uint32_t *) xmalloc ((ctype->plane_size
					       * ctype->plane_cnt + 128)
					      * sizeof (uint32_t));

      /* Copy default value (identity mapping).  */
      memcpy (&ctype->map[idx][128], ctype->names,
	      ctype->plane_size * ctype->plane_cnt * sizeof (uint32_t));

      /* Copy values from collection.  */
      for (idx2 = 0; idx2 < 256; ++idx2)
	ctype->map[idx][128 + idx2] = ctype->map256_collection[idx][idx2];

      /* Mirror first 127 entries.  We must take care not to map entry
	 -1 because EOF == -1.  */
      for (idx2 = 0; idx2 < 127; ++idx2)
	ctype->map[idx][idx2] = ctype->map[idx][256 + idx2];

      /* EOF must map to EOF.  */
      ctype->map[idx][127] = EOF;
    }

  /* Extra array for class and map names.  */
  ctype->class_name_ptr = (uint32_t *) xmalloc (ctype->nr_charclass
						* sizeof (uint32_t));
  ctype->map_name_ptr = (uint32_t *) xmalloc (ctype->map_collection_nr
					      * sizeof (uint32_t));

  /* Array for width information.  Because the expected width are very
     small we use only one single byte.  This save space and we need
     not provide the information twice with both endianesses.  */
  ctype->width = (unsigned char *) xmalloc (ctype->plane_size
					    * ctype->plane_cnt);
  /* Initialize with default width value.  */
  memset (ctype->width, charmap->width_default,
	  ctype->plane_size * ctype->plane_cnt);
  if (charmap->width_rules != NULL)
    {
#if 0
      size_t cnt;

      for (cnt = 0; cnt < charmap->nwidth_rules; ++cnt)
	if (charmap->width_rules[cnt].width != charmap->width_default)
	  for (idx = charmap->width_rules[cnt].from;
	       idx <= charmap->width_rules[cnt].to; ++idx)
	    {
	      size_t nr = idx % ctype->plane_size;
	      size_t depth = 0;

	      while (ctype->names[nr + depth * ctype->plane_size] != nr)
		++depth;
	      assert (depth < ctype->plane_cnt);

	      ctype->width[nr + depth * ctype->plane_size]
		= charmap->width_rules[cnt].width;
	    }
#else
      abort ();
#endif
    }

  /* Set MB_CUR_MAX.  */
  ctype->mb_cur_max = charmap->mb_cur_max;

  /* We need the name of the currently used 8-bit character set to
     make correct conversion between this 8-bit representation and the
     ISO 10646 character set used internally for wide characters.  */
  ctype->codeset_name = charmap->code_set_name;

  /* Now determine the table for the transliteration information.

     XXX It is not yet clear to me whether it is worth implementing a
     complicated algorithm which uses a hash table to locate the entries.
     For now I'll use a simple array which can be searching using binary
     search.  */
  if (ctype->translit_copy_locale != NULL)
    {
      /* Fold in the transliteration information from the locale mentioned
	 in the `include' statement.  */
      struct locale_ctype_t *here = ctype;

      do
	{
	  struct localedef_t *other = find_locale (LC_CTYPE,
						   here->translit_copy_locale,
						   repertoire->name, charmap);

	  if (other == NULL)
	    {
	      error (0, 0, _("\
%s: transliteration data from locale `%s' not available"),
		     "LC_CTYPE", here->translit_copy_locale);
	      break;
	    }

	  here = other->categories[LC_CTYPE].ctype;

	  /* Enqueue the information if necessary.  */
	  if (here->translit != NULL)
	    {
	      struct translit_t *endp = here->translit;
	      while (endp->next != NULL)
		endp = endp->next;

	      endp->next = ctype->translit;
	      ctype->translit = here->translit;
	    }
	}
      while (here->translit_copy_locale != NULL);
    }

  if (ctype->translit != NULL)
    {
      /* First count how many entries we have.  This is the upper limit
	 since some entries from the included files might be overwritten.  */
      size_t number = 0;
      size_t cnt;
      struct translit_t *runp = ctype->translit;
      struct translit_t **sorted;
      size_t from_len, to_len;

      while (runp != NULL)
	{
	  ++number;
	  runp = runp->next;
	}

      /* Next we allocate an array large enough and fill in the values.  */
      sorted = alloca (number * sizeof (struct translit_t **));
      runp = ctype->translit;
      number = 0;
      do
	{
	  /* Search for the place where to insert this string.
	     XXX Better use a real sorting algorithm later.  */
	  size_t idx = 0;
	  int replace = 0;

	  while (idx < number)
	    {
	      int res = wcscmp ((const wchar_t *) sorted[idx]->from,
				(const wchar_t *) runp->from);
	      if (res == 0)
		{
		  replace = 1;
		  break;
		}
	      if (res > 0)
		break;
	      ++idx;
	    }

	  if (replace)
	    sorted[idx] = runp;
	  else
	    {
	      memmove (&sorted[idx + 1], &sorted[idx],
		       (number - idx) * sizeof (struct translit_t *));
	      sorted[idx] = runp;
	      ++number;
	    }

	  runp = runp->next;
	}
      while (runp != NULL);

      /* The next step is putting all the possible transliteration
	 strings in one memory block so that we can write it out.
	 We need several different blocks:
	 - index to the tfromstring array
	 - from-string array
	 - index to the to-string array
	 - to-string array.
	 And this all must be available for both endianes variants.
      */
      from_len = to_len = 0;
      for (cnt = 0; cnt < number; ++cnt)
	{
	  struct translit_to_t *srunp;
	  from_len += wcslen ((const wchar_t *) sorted[cnt]->from) + 1;
	  srunp = sorted[cnt]->to;
	  while (srunp != NULL)
	    {
	      to_len += wcslen ((const wchar_t *) srunp->str) + 1;
	      srunp = srunp->next;
	    }
	  /* Plus one for the extra NUL character marking the end of
	     the list for the current entry.  */
	  ++to_len;
	}

      /* We can allocate the arrays for the results.  */
      ctype->translit_from_idx = xmalloc (number * sizeof (uint32_t));
      ctype->translit_from_tbl = xmalloc (from_len * sizeof (uint32_t));
      ctype->translit_to_idx = xmalloc (number * sizeof (uint32_t));
      ctype->translit_to_tbl = xmalloc (to_len * sizeof (uint32_t));

      from_len = 0;
      to_len = 0;
      for (cnt = 0; cnt < number; ++cnt)
	{
	  size_t len;
	  struct translit_to_t *srunp;

	  ctype->translit_from_idx[cnt] = from_len;
	  ctype->translit_to_idx[cnt] = to_len;

	  len = wcslen ((const wchar_t *) sorted[cnt]->from) + 1;
	  wmemcpy ((wchar_t *) &ctype->translit_from_tbl[from_len],
		   (const wchar_t *) sorted[cnt]->from, len);
	  from_len += len;

	  ctype->translit_to_idx[cnt] = to_len;
	  srunp = sorted[cnt]->to;
	  while (srunp != NULL)
	    {
	      len = wcslen ((const wchar_t *) srunp->str) + 1;
	      wmemcpy ((wchar_t *) &ctype->translit_to_tbl[to_len],
		       (const wchar_t *) srunp->str, len);
	      to_len += len;
	      srunp = srunp->next;
	    }
	  ctype->translit_to_tbl[to_len++] = L'\0';
	}

      /* Store the information about the length.  */
      ctype->translit_idx_size = number * sizeof (uint32_t);
      ctype->translit_from_tbl_size = from_len * sizeof (uint32_t);
      ctype->translit_to_tbl_size = to_len * sizeof (uint32_t);
    }
  else
    {
      /* Provide some dummy pointers since we have nothing to write out.  */
      static uint32_t no_str = { 0 };

      ctype->translit_from_idx = &no_str;
      ctype->translit_from_tbl = &no_str;
      ctype->translit_to_tbl = &no_str;
      ctype->translit_idx_size = 0;
      ctype->translit_from_tbl_size = 0;
      ctype->translit_to_tbl_size = 0;
    }
}
