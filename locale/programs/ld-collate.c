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

#include <error.h>
#include <stdlib.h>

#include "charmap.h"
#include "localeinfo.h"
#include "linereader.h"
#include "locfile.h"
#include "localedef.h"

/* Uncomment the following line in the production version.  */
/* #define NDEBUG 1 */
#include <assert.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

/* Forward declaration.  */
struct element_t;

/* Data type for list of strings.  */
struct section_list
{
  struct section_list *next;
  /* Name of the section.  */
  const char *name;
  /* First element of this section.  */
  struct element_t *first;
  /* Last element of this section.  */
  struct element_t *last;
  /* These are the rules for this section.  */
  enum coll_sort_rule *rules;
};

struct element_t;

struct element_list_t
{
  /* Number of elements.  */
  int cnt;

  struct element_t **w;
};

/* Data type for collating element.  */
struct element_t
{
  const char *mbs;
  const uint32_t *wcs;
  int order;

  struct element_list_t *weights;

  /* Where does the definition come from.  */
  const char *file;
  size_t line;

  /* Which section does this belong to.  */
  struct section_list *section;

  /* Predecessor and successor in the order list.  */
  struct element_t *last;
  struct element_t *next;
};

/* Data type for collating symbol.  */
struct symbol_t
{
  /* Point to place in the order list.  */
  struct element_t *order;

  /* Where does the definition come from.  */
  const char *file;
  size_t line;
};


/* The real definition of the struct for the LC_COLLATE locale.  */
struct locale_collate_t
{
  int col_weight_max;
  int cur_weight_max;

  /* List of known scripts.  */
  struct section_list *sections;
  /* Current section using definition.  */
  struct section_list *current_section;
  /* There always can be an unnamed section.  */
  struct section_list unnamed_section;
  /* To make handling of errors easier we have another section.  */
  struct section_list error_section;

  /* Number of sorting rules given in order_start line.  */
  uint32_t nrules;

  /* Start of the order list.  */
  struct element_t *start;

  /* The undefined element.  */
  struct element_t undefined;

  /* This is the cursor for `reorder_after' insertions.  */
  struct element_t *cursor;

  /* Remember whether last weight was an ellipsis.  */
  int was_ellipsis;

  /* Known collating elements.  */
  hash_table elem_table;

  /* Known collating symbols.  */
  hash_table sym_table;

  /* Known collation sequences.  */
  hash_table seq_table;

  struct obstack mempool;

  /* The LC_COLLATE category is a bit special as it is sometimes possible
     that the definitions from more than one input file contains information.
     Therefore we keep all relevant input in a list.  */
  struct locale_collate_t *next;
};


/* We have a few global variables which are used for reading all
   LC_COLLATE category descriptions in all files.  */
static int nrules;


static struct section_list *
make_seclist_elem (struct locale_collate_t *collate, const char *string,
		   struct section_list *next)
{
  struct section_list *newp;

  newp = (struct section_list *) obstack_alloc (&collate->mempool,
						sizeof (*newp));
  newp->next = next;
  newp->name = string;
  newp->first = NULL;

  return newp;
}


static struct element_t *
new_element (struct locale_collate_t *collate, const char *mbs,
	     size_t len, const uint32_t *wcs)
{
  struct element_t *newp;

  newp = (struct element_t *) obstack_alloc (&collate->mempool,
					     sizeof (*newp));
  newp->mbs = obstack_copy0 (&collate->mempool, mbs, len);
  newp->wcs = wcs;
  newp->order = 0;

  /* Will be allocated later.  */
  newp->weights = NULL;

  newp->file = NULL;
  newp->line = 0;

  newp->section = NULL;

  newp->last = NULL;
  newp->next = NULL;

  return newp;
}


static struct symbol_t *
new_symbol (struct locale_collate_t *collate)
{
  struct symbol_t *newp;

  newp = (struct symbol_t *) obstack_alloc (&collate->mempool, sizeof (*newp));

  newp->order = NULL;

  newp->file = NULL;
  newp->line = 0;

  return newp;
}


/* Test whether this name is already defined somewhere.  */
static int
check_duplicate (struct linereader *ldfile, struct locale_collate_t *collate,
		 struct charmap_t *charmap, struct repertoire_t *repertoire,
		 const char *symbol, size_t symbol_len)
{
  void *ignore = NULL;

  if (find_entry (&charmap->char_table, symbol, symbol_len, &ignore) == 0)
    {
      lr_error (ldfile, _("`%s' already defined in charmap"), symbol);
      return 1;
    }

  if (find_entry (&repertoire->char_table, symbol, symbol_len, &ignore) == 0)
    {
      lr_error (ldfile, _("`%s' already defined in repertoire"), symbol);
      return 1;
    }

  if (find_entry (&collate->sym_table, symbol, symbol_len, &ignore) == 0)
    {
      lr_error (ldfile, _("`%s' already defined as collating symbol"), symbol);
      return 1;
    }

  if (find_entry (&collate->elem_table, symbol, symbol_len, &ignore) == 0)
    {
      lr_error (ldfile, _("`%s' already defined as collating element"),
		symbol);
      return 1;
    }

  return 0;
}


/* Read the direction specification.  */
static void
read_directions (struct linereader *ldfile, struct token *arg,
		 struct charmap_t *charmap, struct repertoire_t *repertoire,
		 struct locale_collate_t *collate)
{
  int cnt = 0;
  int max = nrules ?: 10;
  enum coll_sort_rule *rules = calloc (max, sizeof (*rules));
  int warned = 0;

  while (1)
    {
      int valid = 0;

      if (arg->tok == tok_forward)
	{
	  if (rules[cnt] & sort_backward)
	    {
	      if (! warned)
		{
		  lr_error (ldfile, _("\
%s: `forward' and `backward' are mutually excluding each other"),
			    "LC_COLLATE");
		  warned = 1;
		}
	    }
	  else if (rules[cnt] & sort_forward)
	    {
	      if (! warned)
		{
		  lr_error (ldfile, _("\
%s: `%s' mentioned twice in definition of weight %d"),
			    "LC_COLLATE", "forward", cnt + 1);
		}
	    }
	  else
	    rules[cnt] |= sort_forward;

	  valid = 1;
	}
      else if (arg->tok == tok_backward)
	{
	  if (rules[cnt] & sort_forward)
	    {
	      if (! warned)
		{
		  lr_error (ldfile, _("\
%s: `forward' and `backward' are mutually excluding each other"),
			    "LC_COLLATE");
		  warned = 1;
		}
	    }
	  else if (rules[cnt] & sort_backward)
	    {
	      if (! warned)
		{
		  lr_error (ldfile, _("\
%s: `%s' mentioned twice in definition of weight %d"),
			    "LC_COLLATE", "backward", cnt + 1);
		}
	    }
	  else
	    rules[cnt] |= sort_backward;

	  valid = 1;
	}
      else if (arg->tok == tok_position)
	{
	  if (rules[cnt] & sort_position)
	    {
	      if (! warned)
		{
		  lr_error (ldfile, _("\
%s: `%s' mentioned twice in definition of weight %d in category `%s'"),
			    "LC_COLLATE", "position", cnt + 1);
		}
	    }
	  else
	    rules[cnt] |= sort_position;

	  valid = 1;
	}

      if (valid)
	arg = lr_token (ldfile, charmap, repertoire);

      if (arg->tok == tok_eof || arg->tok == tok_eol || arg->tok == tok_comma
	  || arg->tok == tok_semicolon)
	{
	  if (! valid && ! warned)
	    {
	      lr_error (ldfile, _("%s: syntax error"), "LC_COLLATE");
	      warned = 1;
	    }

	  /* See whether we have to increment the counter.  */
	  if (arg->tok != tok_comma && rules[cnt] != 0)
	    ++cnt;

	  if (arg->tok == tok_eof || arg->tok == tok_eol)
	    /* End of line or file, so we exit the loop.  */
	    break;

	  if (nrules == 0)
	    {
	      /* See whether we have enough room in the array.  */
	      if (cnt == max)
		{
		  max += 10;
		  rules = (enum coll_sort_rule *) xrealloc (rules,
							    max
							    * sizeof (*rules));
		  memset (&rules[cnt], '\0', (max - cnt) * sizeof (*rules));
		}
	    }
	  else
	    {
	      if (cnt == nrules)
		{
		  /* There must not be any more rule.  */
		  if (! warned)
		    {
		      lr_error (ldfile, _("\
%s: too many rules; first entry only had %d"),
				"LC_COLLATE", nrules);
		      warned = 1;
		    }

		  lr_ignore_rest (ldfile, 0);
		  break;
		}
	    }
	}
      else
	{
	  if (! warned)
	    {
	      lr_error (ldfile, _("%s: syntax error"), "LC_COLLATE");
	      warned = 1;
	    }
	}

      arg = lr_token (ldfile, charmap, repertoire);
    }

  if (nrules == 0)
    {
      /* Now we know how many rules we have.  */
      nrules = cnt;
      rules = (enum coll_sort_rule *) xrealloc (rules,
						nrules * sizeof (*rules));
    }
  else
    {
      if (cnt < nrules)
	{
	  /* Not enough rules in this specification.  */
	  if (! warned)
	    lr_error (ldfile, _("%s: not enough sorting rules"), "LC_COLLATE");

	  do
	    rules[cnt] = sort_forward;
	  while (++cnt < nrules);
	}
    }

  collate->current_section->rules = rules;
}


static struct element_t *
find_element (struct linereader *ldfile, struct locale_collate_t *collate,
	      const char *str, size_t len, uint32_t *wcstr)
{
  struct element_t *result = NULL;

  /* Search for the entries among the collation sequences already define.  */
  if (find_entry (&collate->seq_table, str, len, (void **) &result) != 0)
    {
      /* Nope, not define yet.  So we see whether it is a
         collation symbol.  */
      void *ptr;

      if (find_entry (&collate->sym_table, str, len, &ptr) == 0)
	{
	  /* It's a collation symbol.  */
	  struct symbol_t *sym = (struct symbol_t *) ptr;
	  result = sym->order;

	  if (result == NULL)
	    result = sym->order = new_element (collate, str, len, NULL);
	}
      else if (find_entry (&collate->elem_table, str, len,
			   (void **) &result) != 0)
	{
	  /* It's also no collation element.  So it is an element defined
	     later.  */
	  result = new_element (collate, str, len, wcstr);
	  if (result != NULL)
	    /* Insert it into the sequence table.  */
	    insert_entry (&collate->seq_table, str, len, result);
	}
    }

  return result;
}


static void
insert_weights (struct linereader *ldfile, struct element_t *elem,
		struct charmap_t *charmap, struct repertoire_t *repertoire,
		struct locale_collate_t *collate)
{
  int weight_cnt;
  struct token *arg;

  /* Initialize all the fields.  */
  elem->file = ldfile->fname;
  elem->line = ldfile->lineno;
  elem->last = collate->cursor;
  elem->next = collate->cursor ? collate->cursor->next : NULL;
  elem->weights = (struct element_list_t *)
    obstack_alloc (&collate->mempool, nrules * sizeof (struct element_list_t));
  memset (elem->weights, '\0', nrules * sizeof (struct element_list_t));

  if (collate->current_section->first == NULL)
    collate->current_section->first = elem;
  if (collate->current_section->last == collate->cursor)
    collate->current_section->last = elem;

  collate->cursor = elem;

  weight_cnt = 0;

  arg = lr_token (ldfile, charmap, repertoire);
  do
    {
      if (arg->tok == tok_eof || arg->tok == tok_eol)
	break;

      if (arg->tok == tok_ignore)
	{
	  /* The weight for this level has to be ignored.  We use the
	     null pointer to indicate this.  */
	  elem->weights[weight_cnt].w = (struct element_t **)
	    obstack_alloc (&collate->mempool, sizeof (struct element_t *));
	  elem->weights[weight_cnt].w[0] = NULL;
	  elem->weights[weight_cnt].cnt = 0;
	}
      else if (arg->tok == tok_bsymbol)
	{
	  struct element_t *val = find_element (ldfile, collate,
						arg->val.str.startmb,
						arg->val.str.lenmb,
						arg->val.str.startwc);

	  if (val == NULL)
	    break;

	  elem->weights[weight_cnt].w = (struct element_t **)
	    obstack_alloc (&collate->mempool, sizeof (struct element_t *));
	  elem->weights[weight_cnt].w[0] = val;
	  elem->weights[weight_cnt].cnt = 1;
	}
      else if (arg->tok == tok_string)
	{
	  /* Split the string up in the individual characters and put
	     the element definitions in the list.  */
	  const char *cp = arg->val.str.startmb;
	  int cnt = 0;
	  struct element_t *charelem;
	  void *base = obstack_base (&collate->mempool);

	  if (*cp == '\0')
	    {
	      lr_error (ldfile, _("%s: empty weight string not allowed"),
			"LC_COLLATE");
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  do
	    {
	      if (*cp == '<')
		{
		  /* Ahh, it's a bsymbol.  That's what we want.  */
		  const char *startp = cp;

		  while (*++cp != '>')
		    {
		      if (*cp == ldfile->escape_char)
			++cp;
		      if (*cp == '\0')
			{
			  /* It's a syntax error.  */
			  obstack_free (&collate->mempool, base);
			  goto syntax;
			}
		    }

		    charelem = find_element (ldfile, collate, startp,
					     cp - startp, NULL);
		    ++cp;
		}
	      else
		{
		  /* People really shouldn't use characters directly in
		     the string.  Especially since it's not really clear
		     what this means.  We interpret all characters in the
		     string as if that would be bsymbols.  Otherwise we
		     would have to match back to bsymbols somehow and this
		     is also not what people normally expect.  */
		  charelem = find_element (ldfile, collate, cp++, 1, NULL);
		}

	      if (charelem == NULL)
		{
		  /* We ignore the rest of the line.  */
		  lr_ignore_rest (ldfile, 0);
		  break;
		}

	      /* Add the pointer.  */
	      obstack_ptr_grow (&collate->mempool, charelem);
	      ++cnt;
	    }
	  while (*cp != '\0');

	  /* Now store the information.  */
	  elem->weights[weight_cnt].w = (struct element_t **)
	    obstack_finish (&collate->mempool);
	  elem->weights[weight_cnt].cnt = cnt;

	  /* We don't need the string anymore.  */
	  free (arg->val.str.startmb);
	}
      else
	{
	syntax:
	  /* It's a syntax error.  */
	  lr_error (ldfile, _("%s: syntax error"), "LC_COLLATE");
	  lr_ignore_rest (ldfile, 0);
	  break;
	}

      arg = lr_token (ldfile, charmap, repertoire);
      /* This better should be the end of the line or a semicolon.  */
      if (arg->tok == tok_semicolon)
	/* OK, ignore this and read the next token.  */
	arg = lr_token (ldfile, charmap, repertoire);
      else if (arg->tok != tok_eof && arg->tok != tok_eol)
	{
	  /* It's a syntax error.  */
	  lr_error (ldfile, _("%s: syntax error"), "LC_COLLATE");
	  lr_ignore_rest (ldfile, 0);
	  break;
	}
    }
  while (++weight_cnt < nrules);

  if (weight_cnt < nrules)
    {
      /* This means the rest of the line uses the current element as
	 the weight.  */
      do
	{
	  elem->weights[weight_cnt].w = (struct element_t **)
	    obstack_alloc (&collate->mempool, sizeof (struct element_t *));
	  elem->weights[weight_cnt].w[0] = elem;
	  elem->weights[weight_cnt].cnt = 1;
	}
      while (++weight_cnt < nrules);
    }
  else
    {
      if (arg->tok == tok_ignore || arg->tok == tok_bsymbol)
	{
	  /* Too many rule values.  */
	  lr_error (ldfile, _("%s: too many values"), "LC_COLLATE");
	  lr_ignore_rest (ldfile, 0);
	}
      else
	lr_ignore_rest (ldfile, arg->tok != tok_eol && arg->tok != tok_eof);
    }
}


static void
insert_value (struct linereader *ldfile, struct token *arg,
	      struct charmap_t *charmap, struct repertoire_t *repertoire,
	      struct locale_collate_t *collate)
{
  /* First find out what kind of symbol this is.  */
  struct charseq *seq;
  uint32_t wc;
  struct element_t *elem = NULL;

  /* First determine the wide character.  There must be such a value,
     otherwise we ignore it (if it is no collatio symbol or element).  */
  wc = repertoire_find_value (repertoire, arg->val.str.startmb,
			      arg->val.str.lenmb);

  /* Try to find the character in the charmap.  */
  seq = charmap_find_value (charmap, arg->val.str.startmb, arg->val.str.lenmb);

  if (wc == ILLEGAL_CHAR_VALUE && seq == NULL)
    {
      /* It's no character, so look through the collation elements and
	 symbol list.  */
      void *result;

      if (find_entry (&collate->sym_table, arg->val.str.startmb,
		      arg->val.str.lenmb, &result) == 0)
	{
	  /* It's a collation symbol.  */
	  struct symbol_t *sym = (struct symbol_t *) result;
	  elem = sym->order;

	  if (elem == NULL)
	    elem = sym->order = new_element (collate, arg->val.str.startmb,
					     arg->val.str.lenmb,
					     arg->val.str.startwc);
	}
      else if (find_entry (&collate->elem_table, arg->val.str.startmb,
			   arg->val.str.lenmb, (void **) &elem) != 0)
	{
	  /* It's also no collation element.  Therefore ignore it.  */
	  lr_ignore_rest (ldfile, 0);
	  return;
	}
    }
  else
    {
      /* Otherwise the symbols stands for a character.  */
      if (find_entry (&collate->seq_table, arg->val.str.startmb,
		      arg->val.str.lenmb, (void **) &elem) != 0)
	{
	  /* We have to allocate an entry.  */
	  elem = new_element (collate, arg->val.str.startmb,
			      arg->val.str.lenmb,
			      arg->val.str.startwc);

	  /* And add it to the table.  */
	  if (insert_entry (&collate->seq_table, arg->val.str.startmb,
			    arg->val.str.lenmb, elem) != 0)
	    /* This cannot happen.  */
	    abort ();
	}
    }

  /* Test whether this element is not already in the list.  */
  if (elem->next != NULL || (collate->cursor != NULL
			     && elem->next == collate->cursor))
    {
      lr_error (ldfile, _("order for `%.*s' already defined at %s:%Z"),
		arg->val.str.lenmb, arg->val.str.startmb,
		elem->file, elem->line);
      lr_ignore_rest (ldfile, 0);
      return;
    }

  insert_weights (ldfile, elem, charmap, repertoire, collate);
}


static void
collate_startup (struct linereader *ldfile, struct localedef_t *locale,
		 struct localedef_t *copy_locale, int ignore_content)
{
  if (!ignore_content)
    {
      struct locale_collate_t *collate;

      if (copy_locale == NULL)
	{
	  collate = locale->categories[LC_COLLATE].collate =
	    (struct locale_collate_t *)
	    xcalloc (1, sizeof (struct locale_collate_t));

	  /* Init the various data structures.  */
	  init_hash (&collate->elem_table, 100);
	  init_hash (&collate->sym_table, 100);
	  init_hash (&collate->seq_table, 500);
	  obstack_init (&collate->mempool);

	  collate->col_weight_max = -1;
	}
      else
	collate = locale->categories[LC_COLLATE].collate =
	  copy_locale->categories[LC_COLLATE].collate;
    }

  ldfile->translate_strings = 0;
  ldfile->return_widestr = 0;
}


void
collate_finish (struct localedef_t *locale, struct charmap_t *charmap)
{
}


void
collate_output (struct localedef_t *locale, struct charmap_t *charmap,
		const char *output_path)
{
}


void
collate_read (struct linereader *ldfile, struct localedef_t *result,
	      struct charmap_t *charmap, const char *repertoire_name,
	      int ignore_content)
{
  struct repertoire_t *repertoire = NULL;
  struct locale_collate_t *collate;
  struct token *now;
  struct token *arg = NULL;
  enum token_t nowtok;
  int state = 0;
  int was_ellipsis = 0;
  struct localedef_t *copy_locale = NULL;

  /* Get the repertoire we have to use.  */
  if (repertoire_name != NULL)
    repertoire = repertoire_read (repertoire_name);

  /* The rest of the line containing `LC_COLLATE' must be free.  */
  lr_ignore_rest (ldfile, 1);

  do
    {
      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }
  while (nowtok == tok_eol);

  if (nowtok == tok_copy)
    {
      state = 2;
      now = lr_token (ldfile, charmap, NULL);
      if (now->tok != tok_string)
	{
	  SYNTAX_ERROR (_("%s: syntax error"), "LC_COLLATE");

	skip_category:
	  do
	    now = lr_token (ldfile, charmap, NULL);
	  while (now->tok != tok_eof && now->tok != tok_end);

	  if (now->tok != tok_eof
	      || (now = lr_token (ldfile, charmap, NULL), now->tok == tok_eof))
	    lr_error (ldfile, _("%s: premature end of file"), "LC_COLLATE");
	  else if (now->tok != tok_lc_collate)
	    {
	      lr_error (ldfile, _("\
%1$s: definition does not end with `END %1$s'"), "LC_COLLATE");
	      lr_ignore_rest (ldfile, 0);
	    }
	  else
	    lr_ignore_rest (ldfile, 1);

	  return;
	}

      /* Get the locale definition.  */
      copy_locale = find_locale (LC_COLLATE, now->val.str.startmb,
				 repertoire_name, charmap);
      if ((copy_locale->avail & COLLATE_LOCALE) == 0)
	{
	  /* Not yet loaded.  So do it now.  */
	  if (locfile_read (copy_locale, charmap) != 0)
	    goto skip_category;
	}

      lr_ignore_rest (ldfile, 1);

      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }

  /* Prepare the data structures.  */
  collate_startup (ldfile, result, copy_locale, ignore_content);
  collate = result->categories[LC_COLLATE].collate;

  while (1)
    {
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
	case tok_coll_weight_max:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 0)
	    goto err_label;

	  arg = lr_token (ldfile, charmap, NULL);
	  if (arg->tok != tok_number)
	    goto err_label;
	  if (collate->col_weight_max != -1)
	    lr_error (ldfile, _("%s: duplicate definition of `%s'"),
		      "LC_COLLATE", "col_weight_max");
	  else
	    collate->col_weight_max = arg->val.num;
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_section_symbol:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 0)
	    goto err_label;

	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok != tok_bsymbol)
	    goto err_label;
	  else if (!ignore_content)
	    {
	      /* Check whether this section is already known.  */
	      struct section_list *known = collate->sections;
	      while (known != NULL)
		if (strcmp (known->name, arg->val.str.startmb) == 0)
		  break;

	      if (known != NULL)
		{
		  lr_error (ldfile,
			    _("%s: duplicate declaration of section `%s'"),
			    "LC_COLLATE", arg->val.str.startmb);
		  free (arg->val.str.startmb);
		}
	      else
		collate->sections = make_seclist_elem (collate,
						       arg->val.str.startmb,
						       collate->sections);

	      lr_ignore_rest (ldfile, known == NULL);
	    }
	  else
	    {
	      free (arg->val.str.startmb);
	      lr_ignore_rest (ldfile, 0);
	    }
	  break;

	case tok_collating_element:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 0)
	    goto err_label;

	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok != tok_bsymbol)
	    goto err_label;
	  else
	    {
	      const char *symbol = arg->val.str.startmb;
	      size_t symbol_len = arg->val.str.lenmb;

	      /* Next the `from' keyword.  */
	      arg = lr_token (ldfile, charmap, repertoire);
	      if (arg->tok != tok_from)
		{
		  free ((char *) symbol);
		  goto err_label;
		}

	      ldfile->return_widestr = 1;

	      /* Finally the string with the replacement.  */
	      arg = lr_token (ldfile, charmap, repertoire);
	      ldfile->return_widestr = 0;
	      if (arg->tok != tok_string)
		goto err_label;

	      if (!ignore_content)
		{
		  if (symbol == NULL)
		    lr_error (ldfile, _("\
%s: unknown character in collating element name"),
			      "LC_COLLATE");
		  if (arg->val.str.startmb == NULL)
		    lr_error (ldfile, _("\
%s: unknown character in collating element definition"),
			      "LC_COLLATE");
		  if (arg->val.str.startwc == NULL)
		    lr_error (ldfile, _("\
%s: unknown wide character in collating element definition"),
			      "LC_COLLATE");
		  else if (arg->val.str.lenwc < 2)
		    lr_error (ldfile, _("\
%s: substitution string in collating element definition must have at least two characters"),
			      "LC_COLLATE");

		  if (symbol != NULL)
		    {
		      /* The name is already defined.  */
		      if (check_duplicate (ldfile, collate, charmap,
					   repertoire, symbol, symbol_len))
			goto col_elem_free;

		      if (insert_entry (&collate->elem_table,
					symbol, symbol_len,
					new_element (collate,
						     arg->val.str.startmb,
						     arg->val.str.lenmb,
						     arg->val.str.startwc))
			  < 0)
			lr_error (ldfile, _("\
error while adding collating element"));
		    }
		  else
		    goto col_elem_free;
		}
	      else
		{
		col_elem_free:
		  if (symbol != NULL)
		    free ((char *) symbol);
		  if (arg->val.str.startmb != NULL)
		    free (arg->val.str.startmb);
		  if (arg->val.str.startwc != NULL)
		    free (arg->val.str.startwc);
		}
	      lr_ignore_rest (ldfile, 1);
	    }
	  break;

	case tok_collating_symbol:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 0)
	    goto err_label;

	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok != tok_bsymbol)
	    goto err_label;
	  else
	    {
	      const char *symbol = arg->val.str.startmb;
	      size_t symbol_len = arg->val.str.lenmb;

	      if (!ignore_content)
		{
		  if (symbol == NULL)
		    lr_error (ldfile, _("\
%s: unknown character in collating symbol name"),
			      "LC_COLLATE");
		  else
		    {
		      /* The name is already defined.  */
		      if (check_duplicate (ldfile, collate, charmap,
					   repertoire, symbol, symbol_len))
			goto col_sym_free;

		      if (insert_entry (&collate->sym_table,
					symbol, symbol_len,
					new_symbol (collate)) < 0)
			lr_error (ldfile, _("\
error while adding collating symbol"));
		    }
		}
	      else
		{
		col_sym_free:
		  if (symbol != NULL)
		    free ((char *) symbol);
		}
	      lr_ignore_rest (ldfile, 1);
	    }
	  break;

	case tok_symbol_equivalence:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 0)
	    goto err_label;

	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok != tok_bsymbol)
	    goto err_label;
	  else
	    {
	      const char *newname = arg->val.str.startmb;
	      size_t newname_len = arg->val.str.lenmb;
	      const char *symname;
	      size_t symname_len;
	      struct symbol_t *symval;

	      arg = lr_token (ldfile, charmap, repertoire);
	      if (arg->tok != tok_bsymbol)
		{
		  if (newname != NULL)
		    free ((char *) newname);
		  goto err_label;
		}

	      symname = arg->val.str.startmb;
	      symname_len = arg->val.str.lenmb;

	      if (!ignore_content)
		{
		  if (newname == NULL)
		    {
		      lr_error (ldfile, _("\
%s: unknown character in equivalent definition name"),
				"LC_COLLATE");
		      goto sym_equiv_free;
		    }
		  if (symname == NULL)
		    {
		      lr_error (ldfile, _("\
%s: unknown character in equivalent definition value"),
				"LC_COLLATE");
		      goto sym_equiv_free;
		    }
		  /* The name is already defined.  */
		  if (check_duplicate (ldfile, collate, charmap,
				       repertoire, symname, symname_len))
		    goto col_sym_free;

		  /* See whether the symbol name is already defined.  */
		  if (find_entry (&collate->sym_table, symname, symname_len,
				  (void **) &symval) != 0)
		    {
		      lr_error (ldfile, _("\
%s: unknown symbol `%s' in equivalent definition"),
				"LC_COLLATE", symname);
		      goto col_sym_free;
		    }

		  if (insert_entry (&collate->sym_table,
				    newname, newname_len, symval) < 0)
		    {
		      lr_error (ldfile, _("\
error while adding equivalent collating symbol"));
		      goto sym_equiv_free;
		    }

		  free ((char *) symname);
		}
	      else
		{
		sym_equiv_free:
		  if (newname != NULL)
		    free ((char *) newname);
		  if (symname != NULL)
		    free ((char *) symname);
		}
	      lr_ignore_rest (ldfile, 1);
	    }
	  break;

	case tok_order_start:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 0 && state != 1)
	    goto err_label;
	  state = 1;

	  /* The 14652 draft does not specify whether all `order_start' lines
	     must contain the same number of sort-rules, but 14651 does.  So
	     we require this here as well.  */
	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok == tok_bsymbol)
	    {
	      /* This better should be a section name.  */
	      struct section_list *sp = collate->sections;
	      while (sp != NULL
		     && strcmp (sp->name, arg->val.str.startmb) != 0)
		sp = sp->next;

	      if (sp == NULL)
		{
		  lr_error (ldfile, _("\
%s: unknown section name `%s'"),
			    "LC_COLLATE", arg->val.str.startmb);
		  /* We use the error section.  */
		  collate->current_section = &collate->error_section;
		}
	      else
		{
		  /* Remember this section.  */
		  collate->current_section = sp;

		  /* One should not be allowed to open the same
                     section twice.  */
		  if (sp->first != NULL)
		    lr_error (ldfile, _("\
%s: multiple order definitions for section `%s'"),
			      "LC_COLLATE", sp->name);

		  /* Next should come the end of the line or a semicolon.  */
		  arg = lr_token (ldfile, charmap, repertoire);
		  if (arg->tok == tok_eol)
		    {
		      uint32_t cnt;

		      /* This means we have exactly one rule: `forward'.  */
		      if (collate->nrules > 1)
			lr_error (ldfile, _("\
%s: invalid number of sorting rules"),
				  "LC_COLLATE");
		      else
			collate->nrules = 1;
		      sp->rules = obstack_alloc (&collate->mempool,
						 (sizeof (enum coll_sort_rule)
						  * collate->nrules));
		      for (cnt = 0; cnt < collate->nrules; ++cnt)
			sp->rules[cnt] = sort_forward;

		      /* Next line.  */
		      break;
		    }

		  /* Get the next token.  */
		  arg = lr_token (ldfile, charmap, repertoire);
		}
	    }
	  else
	    {
	      /* There is no section symbol.  Therefore we use the unnamed
		 section.  */
	      collate->current_section = &collate->unnamed_section;

	      if (collate->unnamed_section.first != NULL)
		lr_error (ldfile, _("\
%s: multiple order definitions for unnamed section"),
			  "LC_COLLATE");
	    }

	  /* Now read the direction names.  */
	  read_directions (ldfile, arg, charmap, repertoire, collate);

	  /* From now be need the strings untranslated.  */
	  ldfile->translate_strings = 0;
	  break;

	case tok_order_end:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 1)
	    goto err_label;
	  state = 2;
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_reorder_after:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 2 && state != 3)
	    goto err_label;
	  state = 3;

	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok == tok_bsymbol)
	    {
	      /* Find this symbol in the sequence table.  */
	      struct element_t *insp;
	      int no_error = 1;

	      if (find_entry (&collate->seq_table, arg->val.str.startmb,
			      arg->val.str.lenmb, (void **) &insp) == 0)
		/* Yes, the symbol exists.  Simply point the cursor
		   to it.  */
		  collate->cursor = insp;
	      else
		{
		  /* This is bad.  The symbol after which we have to
                     insert does not exist.  */
		  lr_error (ldfile, _("\
%s: cannot reorder after %.*s: symbol not known"),
			    "LC_COLLATE", arg->val.str.lenmb,
			    arg->val.str.startmb);
		  collate->cursor = NULL;
		  no_error = 0;
		}

	      lr_ignore_rest (ldfile, no_error);
	    }
	  else
	    /* This must not happen.  */
	    goto err_label;
	  break;

	case tok_reorder_end:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    break;

	  if (state != 3)
	    goto err_label;
	  state = 4;
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_reorder_sections_after:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 2 && state != 4)
	    goto err_label;
	  state = 5;

	  /* Get the name of the sections we are adding after.  */
	  arg = lr_token (ldfile, charmap, repertoire);
	  if (arg->tok == tok_bsymbol)
	    {
	      /* Now find a section with this name.  */
	      struct section_list *runp = collate->sections;

	      while (runp != NULL)
		{
		  if (runp->name != NULL
		      && strlen (runp->name) == arg->val.str.lenmb
		      && memcmp (runp->name, arg->val.str.startmb,
				 arg->val.str.lenmb) == 0)
		    break;

		  runp = runp->next;
		}

	      if (runp != NULL)
		collate->current_section = runp;
	      else
		{
		  /* This is bad.  The section after which we have to
                     reorder does not exist.  Therefore we cannot
                     process the whole rest of this reorder
                     specification.  */
		  lr_error (ldfile, _("%s: section `%.*s' not known"),
			    "LC_COLLATE", arg->val.str.lenmb,
			    arg->val.str.startmb);

		  do
		    {
		      lr_ignore_rest (ldfile, 0);

		      now = lr_token (ldfile, charmap, NULL);
		    }
		  while (now->tok == tok_reorder_sections_after
			 || now->tok == tok_reorder_sections_end
			 || now->tok == tok_end);

		  /* Process the token we just saw.  */
		  nowtok = now->tok;
		  continue;
		}
	    }
	  else
	    /* This must not happen.  */
	    goto err_label;
	  break;

	case tok_reorder_sections_end:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    break;

	  if (state != 5)
	    goto err_label;
	  state = 6;
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_bsymbol:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 1 && state != 3)
	    goto err_label;

	  if (state == 3)
	    {
	      /* It is possible that we already have this collation sequence.
		 In this case we move the entry.  */
	      struct element_t *seqp;

	      /* If the symbol after which we have to insert was not found
		 ignore all entries.  */
	      if (collate->cursor == NULL)
		{
		  lr_ignore_rest (ldfile, 0);
		  break;
		}

	      if (find_entry (&collate->seq_table, arg->val.str.startmb,
			      arg->val.str.lenmb, (void **) &seqp) == 0)
		{
		  /* Remove the entry from the old position.  */
		  if (seqp->last == NULL)
		    collate->start = seqp->next;
		  else
		    seqp->last->next = seqp->next;
		  if (seqp->next != NULL)
		    seqp->next->last = seqp->last;

		  /* We also have to check whether this entry is the
                     first or last of a section.  */
		  if (seqp->section->first == seqp)
		    {
		      if (seqp->section->first == seqp->section->last)
			/* This setion has no content anymore.  */
			seqp->section->first = seqp->section->last = NULL;
		      else
			seqp->section->first = seqp->next;
		    }
		  else if (seqp->section->last == seqp)
		    seqp->section->last = seqp->last;

		  /* Now insert it in the new place.  */
		  seqp->next = collate->cursor->next;
		  seqp->last = collate->cursor;
		  collate->cursor->next = seqp;
		  if (seqp->next != NULL)
		    seqp->next->last = seqp;

		  seqp->section = collate->cursor->section;
		  if (seqp->section->last == collate->cursor)
		    seqp->section->last = seqp;

		  break;
		}

	      /* Otherwise we just add a new entry.  */
	    }
	  else if (state == 5)
	    {
	      /* We are reordering sections.  Find the named section.  */
	      struct section_list *runp = collate->sections;
	      struct section_list *prevp = NULL;

	      while (runp != NULL)
		{
		  if (runp->name != NULL
		      && strlen (runp->name) == arg->val.str.lenmb
		      && memcmp (runp->name, arg->val.str.startmb,
				 arg->val.str.lenmb) == 0)
		    break;

		  prevp = runp;
		  runp = runp->next;
		}

	      if (runp == NULL)
		{
		  lr_error (ldfile, _("%s: section `%.*s' not known"),
			    "LC_COLLATE", arg->val.str.lenmb,
			    arg->val.str.startmb);
		  lr_ignore_rest (ldfile, 0);
		}
	      else
		{
		  if (runp != collate->current_section)
		    {
		      /* Remove the named section from the old place and
			 insert it in the new one.  */
		      prevp->next = runp->next;

		      runp->next = collate->current_section->next;
		      collate->current_section->next = runp;
		      collate->current_section = runp;
		    }

		  /* Process the rest of the line which might change
                     the collation rules.  */
		  arg = lr_token (ldfile, charmap, repertoire);
		  if (arg->tok != tok_eof && arg->tok != tok_eol)
		    read_directions (ldfile, arg, charmap, repertoire,
				     collate);
		}
	    }

	  /* Now insert in the new place.  */
	  insert_value (ldfile, arg, charmap, repertoire, collate);
	  break;

	case tok_undefined:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 1)
	    goto err_label;

	  /* See whether UNDEFINED already appeared somewhere.  */
	  if (collate->undefined.next != NULL
	      || (collate->cursor != NULL
		  && collate->undefined.next == collate->cursor))
	    {
	      lr_error (ldfile, _("order for `%.*s' already defined at %s:%Z"),
			9, "UNDEFINED", collate->undefined.file,
			collate->undefined.line);
	      lr_ignore_rest (ldfile, 0);
	    }
	  else
	    /* Parse the weights.  */
	     insert_weights (ldfile, &collate->undefined, charmap,
			     repertoire, collate);
	  break;

	case tok_ellipsis3:
	  /* Ignore the rest of the line if we don't need the input of
	     this line.  */
	  if (ignore_content)
	    {
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }

	  if (state != 1 && state != 3)
	    goto err_label;

	  was_ellipsis = 1;
	  /* XXX Read the remainder of the line and remember what are
	     the weights.  */
	  break;

	case tok_end:
	  /* Next we assume `LC_COLLATE'.  */
	  if (!ignore_content)
	    {
	      if (state == 0)
		/* We must either see a copy statement or have
		   ordering values.  */
		lr_error (ldfile,
			  _("%s: empty category description not allowed"),
			  "LC_COLLATE");
	      else if (state == 1)
		lr_error (ldfile, _("%s: missing `order_end' keyword"),
			  "LC_COLLATE");
	      else if (state == 3)
		error (0, 0, _("%s: missing `reorder-end' keyword"),
		       "LC_COLLATE");
	      else if (state == 5)
		error (0, 0, _("%s: missing `reorder-sections-end' keyword"),
		       "LC_COLLATE");
	    }
	  arg = lr_token (ldfile, charmap, NULL);
	  if (arg->tok == tok_eof)
	    break;
	  if (arg->tok == tok_eol)
	    lr_error (ldfile, _("%s: incomplete `END' line"), "LC_COLLATE");
	  else if (arg->tok != tok_lc_collate)
	    lr_error (ldfile, _("\
%1$s: definition does not end with `END %1$s'"), "LC_COLLATE");
	  lr_ignore_rest (ldfile, arg->tok == tok_lc_collate);
	  return;

	default:
	err_label:
	  SYNTAX_ERROR (_("%s: syntax error"), "LC_COLLATE");
	}

      /* Prepare for the next round.  */
      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }

  /* When we come here we reached the end of the file.  */
  lr_error (ldfile, _("%s: premature end of file"), "LC_COLLATE");
}


#if 0

/* What kind of symbols get defined?  */
enum coll_symbol
{
  undefined,
  ellipsis,
  character,
  element,
  symbol
};


typedef struct patch_t
{
  const char *fname;
  size_t lineno;
  const char *token;
  union
  {
    unsigned int *pos;
    size_t idx;
  } where;
  struct patch_t *next;
} patch_t;


typedef struct element_t
{
  const char *namemb;
  const uint32_t *namewc;
  unsigned int this_weight;

  struct element_t *next;

  unsigned int *ordering;
  size_t ordering_len;
} element_t;


/* The real definition of the struct for the LC_COLLATE locale.  */
struct locale_collate_t
{
  /* Collate symbol table.  Simple mapping to number.  */
  hash_table symbols;

  /* The collation elements.  */
  hash_table elements;
  struct obstack element_mem;

  /* The result tables.  */
  hash_table resultmb;
  hash_table resultwc;

  /* Sorting rules given in order_start line.  */
  uint32_t nrules;
  enum coll_sort_rule *rules;

  /* Used while recognizing symbol composed of multiple tokens
     (collating-element).  */
  const char *combine_token;
  size_t combine_token_len;

  /* How many sorting order specifications so far.  */
  unsigned int order_cnt;

  /* Was lastline ellipsis?  */
  int was_ellipsis;
  /* Value of last entry if was character.  */
  uint32_t last_char;
  /* Current element.  */
  element_t *current_element;
  /* What kind of symbol is current element.  */
  enum coll_symbol kind;

  /* Patch lists.  */
  patch_t *current_patch;
  patch_t *all_patches;

  /* Room for the UNDEFINED information.  */
  element_t undefined;
  unsigned int undefined_len;

  /* Script information.  */
  const char **scripts;
  unsigned int nscripts;
};


/* Be verbose?  Defined in localedef.c.  */
extern int verbose;



#define obstack_chunk_alloc malloc
#define obstack_chunk_free free


/* Prototypes for local functions.  */
static void collate_startup (struct linereader *ldfile,
			     struct localedef_t *locale,
			     struct charmap_t *charmap, int ignore_content);


static void
collate_startup (struct linereader *ldfile, struct localedef_t *locale,
		 struct charmap_t *charset, int ignore_content)
{
  struct locale_collate_t *collate;

  /* Allocate the needed room.  */
  locale->categories[LC_COLLATE].collate = collate =
    (struct locale_collate_t *) xmalloc (sizeof (struct locale_collate_t));

  /* Allocate hash table for collating elements.  */
  if (init_hash (&collate->elements, 512))
    error (4, 0, _("memory exhausted"));
  collate->combine_token = NULL;
  obstack_init (&collate->element_mem);

  /* Allocate hash table for collating elements.  */
  if (init_hash (&collate->symbols, 64))
    error (4, 0, _("memory exhausted"));

  /* Allocate hash table for result.  */
  if (init_hash (&collate->result, 512))
    error (4, 0, _("memory exhausted"));

  collate->nrules = 0;
  collate->nrules_max = 10;
  collate->rules
    = (enum coll_sort_rule *) xmalloc (collate->nrules_max
				       * sizeof (enum coll_sort_rule));

  collate->order_cnt = 1;	/* The smallest weight is 2.  */

  collate->was_ellipsis = 0;
  collate->last_char = L'\0';	/* 0 because leading ellipsis is allowed.  */

  collate->all_patches = NULL;

  /* This tells us no UNDEFINED entry was found until now.  */
  memset (&collate->undefined, '\0', sizeof (collate->undefined));

  ldfile->translate_strings = 0;
  ldfile->return_widestr = 0;
}


void
collate_finish (struct localedef_t *locale, struct charset_t *charset,
		struct repertoire_t *repertoire)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;
  patch_t *patch;
  size_t cnt;

  /* Patch the constructed table so that forward references are
     correctly filled.  */
  for (patch = collate->all_patches; patch != NULL; patch = patch->next)
    {
      uint32_t wch;
      size_t toklen = strlen (patch->token);
      void *ptmp;
      unsigned int value = 0;

      wch = charset_find_value (&charset->char_table, patch->token, toklen);
      if (wch != ILLEGAL_CHAR_VALUE)
	{
	  element_t *runp;

	  if (find_entry (&collate->result, &wch, sizeof (uint32_t),
			  (void *) &runp) < 0)
	    runp = NULL;
	  for (; runp != NULL; runp = runp->next)
	    if (runp->name[0] == wch && runp->name[1] == L'\0')
	      break;

	  value = runp == NULL ? 0 : runp->this_weight;
	}
      else if (find_entry (&collate->elements, patch->token, toklen, &ptmp)
	       >= 0)
	{
	  value = ((element_t *) ptmp)->this_weight;
	}
      else if (find_entry (&collate->symbols, patch->token, toklen, &ptmp)
	       >= 0)
	{
	  value = (unsigned long int) ptmp;
	}
      else
	value = 0;

      if (value == 0)
	{
	  if (!be_quiet)
	    error_at_line (0, 0, patch->fname, patch->lineno,
			   _("no weight defined for symbol `%s'"),
			   patch->token);
	}
      else
	*patch->where.pos = value;
    }

  /* If no definition for UNDEFINED is given, all characters in the
     given charset must be specified.  */
  if (collate->undefined.ordering == NULL)
    {
      /**************************************************************\
      |* XXX We should test whether really an unspecified character *|
      |* exists before giving the message.			    *|
      \**************************************************************/
      uint32_t weight;

      if (!be_quiet)
	error (0, 0, _("no definition of `UNDEFINED'"));

      collate->undefined.ordering_len = collate->nrules;
      weight = ++collate->order_cnt;

      for (cnt = 0; cnt < collate->nrules; ++cnt)
	{
	  uint32_t one = 1;
	  obstack_grow (&collate->element_mem, &one, sizeof (one));
	}

      for (cnt = 0; cnt < collate->nrules; ++cnt)
	obstack_grow (&collate->element_mem, &weight, sizeof (weight));

      collate->undefined.ordering = obstack_finish (&collate->element_mem);
    }

  collate->undefined_len = 2;	/* For the name: 1 x uint32_t + L'\0'.  */
  for (cnt = 0; cnt < collate->nrules; ++cnt)
    collate->undefined_len += 1 + collate->undefined.ordering[cnt];
}



void
collate_output (struct localedef_t *locale, struct charset_t *charset,
		struct repertoire_t *repertoire, const char *output_path)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;
  uint32_t table_size, table_best, level_best, sum_best;
  void *last;
  element_t *pelem;
  uint32_t *name;
  size_t len;
  const size_t nelems = _NL_ITEM_INDEX (_NL_NUM_LC_COLLATE);
  struct iovec iov[2 + nelems];
  struct locale_file data;
  uint32_t idx[nelems];
  struct obstack non_simple;
  struct obstack string_pool;
  size_t cnt, entry_size;
  uint32_t undefined_offset = UINT_MAX;
  uint32_t *table, *extra, *table2, *extra2;
  size_t extra_len;
  uint32_t element_hash_tab_size;
  uint32_t *element_hash_tab;
  uint32_t *element_hash_tab_ob;
  uint32_t element_string_pool_size;
  char *element_string_pool;
  uint32_t element_value_size;
  uint32_t *element_value;
  uint32_t *element_value_ob;
  uint32_t symbols_hash_tab_size;
  uint32_t *symbols_hash_tab;
  uint32_t *symbols_hash_tab_ob;
  uint32_t symbols_string_pool_size;
  char *symbols_string_pool;
  uint32_t symbols_class_size;
  uint32_t *symbols_class;
  uint32_t *symbols_class_ob;
  hash_table *hash_tab;
  unsigned int dummy_weights[collate->nrules + 1];

  sum_best = UINT_MAX;
  table_best = 0xffff;
  level_best = 0xffff;

  /* Compute table size.  */
  if (!be_quiet)
    fputs (_("\
Computing table size for collation information might take a while..."),
	   stderr);
  for (table_size = 256; table_size < sum_best; ++table_size)
    {
      size_t hits[table_size];
      unsigned int worst = 1;
      size_t cnt;

      last = NULL;

      for (cnt = 0; cnt < 256; ++cnt)
	hits[cnt] = 1;
      memset (&hits[256], '\0', sizeof (hits) - 256 * sizeof (size_t));

      while (iterate_table (&collate->result, &last, (const void **) &name,
			    &len, (void **) &pelem) >= 0)
	if (pelem->ordering != NULL && pelem->name[0] > 0xff)
	  if (++hits[(unsigned int) pelem->name[0] % table_size] > worst)
	    {
	      worst = hits[(unsigned int) pelem->name[0] % table_size];
	      if (table_size * worst > sum_best)
		break;
	    }

      if (table_size * worst < sum_best)
	{
	  sum_best = table_size * worst;
	  table_best = table_size;
	  level_best = worst;
	}
    }
  assert (table_best != 0xffff || level_best != 0xffff);
  if (!be_quiet)
    fputs (_(" done\n"), stderr);

  obstack_init (&non_simple);
  obstack_init (&string_pool);

  data.magic = LIMAGIC (LC_COLLATE);
  data.n = nelems;
  iov[0].iov_base = (void *) &data;
  iov[0].iov_len = sizeof (data);

  iov[1].iov_base = (void *) idx;
  iov[1].iov_len = sizeof (idx);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_NRULES)].iov_base = &collate->nrules;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_NRULES)].iov_len = sizeof (uint32_t);

  table = (uint32_t *) alloca (collate->nrules * sizeof (uint32_t));
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_RULES)].iov_base = table;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_RULES)].iov_len
    = collate->nrules * sizeof (uint32_t);
  /* Another trick here.  Describing the collation method needs only a
     few bits (3, to be exact).  But the binary file should be
     accessible by machines with both endianesses and so we store both
     forms in the same word.  */
  for (cnt = 0; cnt < collate->nrules; ++cnt)
    table[cnt] = collate->rules[cnt] | bswap_32 (collate->rules[cnt]);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_HASH_SIZE)].iov_base = &table_best;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_HASH_SIZE)].iov_len = sizeof (uint32_t);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_HASH_LAYERS)].iov_base = &level_best;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_HASH_LAYERS)].iov_len
    = sizeof (uint32_t);

  entry_size = 1 + MAX (collate->nrules, 2);

  table = (uint32_t *) alloca (table_best * level_best * entry_size
				* sizeof (table[0]));
  memset (table, '\0', table_best * level_best * entry_size
	  * sizeof (table[0]));


  /* Macros for inserting in output table.  */
#define ADD_VALUE(expr)							      \
  do {									      \
    uint32_t to_write = (uint32_t) expr;				      \
    obstack_grow (&non_simple, &to_write, sizeof (to_write));		      \
  } while (0)

#define ADD_ELEMENT(pelem, len)						      \
  do {									      \
    size_t cnt, idx;							      \
									      \
    ADD_VALUE (len);							      \
									      \
    wlen = wcslen (pelem->name);					      \
    obstack_grow (&non_simple, pelem->name, (wlen + 1) * sizeof (uint32_t)); \
									      \
    idx = collate->nrules;						      \
    for (cnt = 0; cnt < collate->nrules; ++cnt)				      \
      {									      \
	size_t disp;							      \
									      \
	ADD_VALUE (pelem->ordering[cnt]);				      \
	for (disp = 0; disp < pelem->ordering[cnt]; ++disp)		      \
	  ADD_VALUE (pelem->ordering[idx++]);				      \
      }									      \
  } while (0)

#define ADD_FORWARD(pelem)						      \
  do {									      \
    /* We leave a reference in the main table and put all		      \
       information in the table for the extended entries.  */		      \
    element_t *runp;							      \
    element_t *has_simple = NULL;					      \
    size_t wlen;							      \
									      \
    table[(level * table_best + slot) * entry_size + 1]			      \
      = FORWARD_CHAR;							      \
    table[(level * table_best + slot) * entry_size + 2]			      \
      = obstack_object_size (&non_simple) / sizeof (uint32_t);		      \
									      \
    /* Here we have to construct the non-simple table entry.  First	      \
       compute the total length of this entry.  */			      \
    for (runp = (pelem); runp != NULL; runp = runp->next)		      \
      if (runp->ordering != NULL)					      \
	{								      \
	  uint32_t value;						      \
	  size_t cnt;							      \
									      \
	  value = 1 + wcslen (runp->name) + 1;				      \
									      \
	  for (cnt = 0; cnt < collate->nrules; ++cnt)			      \
	    /* We have to take care for entries without ordering	      \
	       information.  While reading them they get inserted in the      \
	       table and later not removed when something goes wrong with     \
	       reading its weights.  */					      \
	    value += 1 + runp->ordering[cnt];				      \
									      \
	  if (runp->name[1] == L'\0')					      \
	    has_simple = runp;						      \
									      \
	  ADD_ELEMENT (runp, value);					      \
	}								      \
									      \
    if (has_simple == NULL)						      \
      {									      \
	size_t idx, cnt;						      \
									      \
	ADD_VALUE (collate->undefined_len + 1);				      \
									      \
	/* Add the name.  */						      \
	ADD_VALUE ((pelem)->name[0]);					      \
	ADD_VALUE (0);							      \
									      \
	idx = collate->nrules;						      \
	for (cnt = 0; cnt < collate->nrules; ++cnt)			      \
	  {								      \
	    size_t disp;						      \
									      \
	    ADD_VALUE (collate->undefined.ordering[cnt]);		      \
	    for (disp = 0; disp < collate->undefined.ordering[cnt]; ++disp)   \
	      {								      \
		if ((uint32_t) collate->undefined.ordering[idx]		      \
		    == ELLIPSIS_CHAR)					      \
		  ADD_VALUE ((pelem)->name[0]);				      \
		else							      \
		  ADD_VALUE (collate->undefined.ordering[idx++]);	      \
		++idx;							      \
	      }								      \
	  }								      \
      }									      \
  } while (0)



  /* Fill the table now.  First we look for all the characters which
     fit into one single byte.  This speeds up the 8-bit string
     functions.  */
  last = NULL;
  while (iterate_table (&collate->result, &last, (const void **) &name,
			&len, (void **) &pelem) >= 0)
    if (pelem->name[0] <= 0xff)
      {
	/* We have a single byte name.  Now we must distinguish
	   between entries in simple form (i.e., only one value per
	   weight and no collation element starting with the same
	   character) and those which are not.  */
	size_t slot = ((size_t) pelem->name[0]);
	const size_t level = 0;

	table[slot * entry_size] = pelem->name[0];

	if (pelem->name[1] == L'\0' && pelem->next == NULL
	    && pelem->ordering_len == collate->nrules)
	  {
	    /* Yes, we have a simple one.  Lucky us.  */
	    size_t cnt;

	    for (cnt = 0; cnt < collate->nrules; ++cnt)
	      table[slot * entry_size + 1 + cnt]
		= pelem->ordering[collate->nrules + cnt];
	  }
	else
	  ADD_FORWARD (pelem);
      }

  /* Now check for missing single byte entries.  If one exist we fill
     with the UNDEFINED entry.  */
  for (cnt = 0; cnt < 256; ++cnt)
    /* The first weight is never 0 for existing entries.  */
    if (table[cnt * entry_size + 1] == 0)
      {
	/* We have to fill in the information from the UNDEFINED
	   entry.  */
	table[cnt * entry_size] = (uint32_t) cnt;

	if (collate->undefined.ordering_len == collate->nrules)
	  {
	    size_t inner;

	    for (inner = 0; inner < collate->nrules; ++inner)
	      if ((uint32_t)collate->undefined.ordering[collate->nrules
						       + inner]
		  == ELLIPSIS_CHAR)
		table[cnt * entry_size + 1 + inner] = cnt;
	      else
		table[cnt * entry_size + 1 + inner]
		  = collate->undefined.ordering[collate->nrules + inner];
	  }
	else
	  {
	    if (undefined_offset != UINT_MAX)
	      {
		table[cnt * entry_size + 1] = FORWARD_CHAR;
		table[cnt * entry_size + 2] = undefined_offset;
	      }
	    else
	      {
		const size_t slot = cnt;
		const size_t level = 0;

		ADD_FORWARD (&collate->undefined);
		undefined_offset = table[cnt * entry_size + 2];
	      }
	  }
      }

  /* Now we are ready for inserting the whole rest.   */
  last = NULL;
  while (iterate_table (&collate->result, &last, (const void **) &name,
			&len, (void **) &pelem) >= 0)
    if (pelem->name[0] > 0xff)
      {
	/* Find the position.  */
	size_t slot = ((size_t) pelem->name[0]) % table_best;
	size_t level = 0;

	while (table[(level * table_best + slot) * entry_size + 1] != 0)
	  ++level;
	assert (level < level_best);

	if (pelem->name[1] == L'\0' && pelem->next == NULL
	    && pelem->ordering_len == collate->nrules)
	  {
	    /* Again a simple entry.  */
	    size_t inner;

	    for (inner = 0; inner < collate->nrules; ++inner)
	      table[(level * table_best + slot) * entry_size + 1 + inner]
		= pelem->ordering[collate->nrules + inner];
	  }
	else
	  ADD_FORWARD (pelem);
      }

  /* Add the UNDEFINED entry.  */
  {
    /* Here we have to construct the non-simple table entry.  */
    size_t idx, cnt;

    undefined_offset = obstack_object_size (&non_simple);

    idx = collate->nrules;
    for (cnt = 0; cnt < collate->nrules; ++cnt)
      {
	size_t disp;

	ADD_VALUE (collate->undefined.ordering[cnt]);
	for (disp = 0; disp < collate->undefined.ordering[cnt]; ++disp)
	  ADD_VALUE (collate->undefined.ordering[idx++]);
      }
  }

  /* Finish the extra block.  */
  extra_len = obstack_object_size (&non_simple);
  extra = (uint32_t *) obstack_finish (&non_simple);
  assert ((extra_len % sizeof (uint32_t)) == 0);

  /* Now we have to build the two array for the other byte ordering.  */
  table2 = (uint32_t *) alloca (table_best * level_best * entry_size
				 * sizeof (table[0]));
  extra2 = (uint32_t *) alloca (extra_len);

  for (cnt = 0; cnt < table_best * level_best * entry_size; ++cnt)
    table2[cnt] = bswap_32 (table[cnt]);

  for (cnt = 0; cnt < extra_len / sizeof (uint32_t); ++cnt)
    extra2[cnt] = bswap_32 (extra2[cnt]);

  /* We need a simple hashing table to get a collation-element->chars
     mapping.  We again use internal hashing using a secondary hashing
     function.

     Each string has an associate hashing value V, computed by a
     fixed function.  To locate the string we use open addressing with
     double hashing.  The first index will be V % M, where M is the
     size of the hashing table.  If no entry is found, iterating with
     a second, independent hashing function takes place.  This second
     value will be 1 + V % (M - 2).  The approximate number of probes
     will be

	  for unsuccessful search: (1 - N / M) ^ -1
	  for successful search:   - (N / M) ^ -1 * ln (1 - N / M)

     where N is the number of keys.

     If we now choose M to be the next prime bigger than 4 / 3 * N,
     we get the values 4 and 1.85 resp.  Because unsuccessful searches
     are unlikely this is a good value.  Formulas: [Knuth, The Art of
     Computer Programming, Volume 3, Sorting and Searching, 1973,
     Addison Wesley]  */
  if (collate->elements.filled == 0)
    {
      /* We don't need any element table since there are no collating
	 elements.  */
      element_hash_tab_size = 0;
      element_hash_tab = NULL;
      element_hash_tab_ob = NULL;
      element_string_pool_size = 0;
      element_string_pool = NULL;
      element_value_size = 0;
      element_value = NULL;
      element_value_ob = NULL;
    }
  else
    {
      void *ptr;		/* Running pointer.  */
      const char *key;		/* Key for current bucket.  */
      size_t keylen;		/* Length of key data.  */
      const element_t *data;	/* Data, i.e., the character sequence.  */

      element_hash_tab_size = next_prime ((collate->elements.filled * 4) / 3);
      if (element_hash_tab_size < 7)
	/* We need a minimum to make the following code work.  */
	element_hash_tab_size = 7;

      element_hash_tab = obstack_alloc (&non_simple, (2 * element_hash_tab_size
						      * sizeof (uint32_t)));
      memset (element_hash_tab, '\377', (2 * element_hash_tab_size
					 * sizeof (uint32_t)));

      ptr = NULL;
      while (iterate_table (&collate->elements, &ptr, (const void **) &key,
			    &keylen, (void **) &data) == 0)
	{
	  size_t hash_val = hash_string (key, keylen);
	  size_t idx = hash_val % element_hash_tab_size;

	  if (element_hash_tab[2 * idx] != (~((uint32_t) 0)))
	    {
	      /* We need the second hashing function.  */
	      size_t c = 1 + (hash_val % (element_hash_tab_size - 2));

	      do
		if (idx >= element_hash_tab_size - c)
		  idx -= element_hash_tab_size - c;
		else
		  idx += c;
	      while (element_hash_tab[2 * idx] != (~((uint32_t) 0)));
	    }

	  element_hash_tab[2 * idx] = obstack_object_size (&non_simple);
	  element_hash_tab[2 * idx + 1] = (obstack_object_size (&string_pool)
					   / sizeof (uint32_t));

	  obstack_grow0 (&non_simple, key, keylen);
	  obstack_grow (&string_pool, data->name,
			(wcslen (data->name) + 1) * sizeof (uint32_t));
	}

      if (obstack_object_size (&non_simple) % 4 != 0)
	obstack_blank (&non_simple,
		       4 - (obstack_object_size (&non_simple) % 4));
      element_string_pool_size = obstack_object_size (&non_simple);
      element_string_pool = obstack_finish (&non_simple);

      element_value_size = obstack_object_size (&string_pool);
      element_value = obstack_finish (&string_pool);

      /* Create the tables for the other byte order.  */
      element_hash_tab_ob = obstack_alloc (&non_simple,
					   (2 * element_hash_tab_size
					    * sizeof (uint32_t)));
      for (cnt = 0; cnt < 2 * element_hash_tab_size; ++cnt)
	element_hash_tab_ob[cnt] = bswap_U32 (element_hash_tab[cnt]);

      element_value_ob = obstack_alloc (&string_pool, element_value_size);
      for (cnt = 0; cnt < element_value_size / 4; ++cnt)
	element_value_ob[cnt] = bswap_32 (element_value[cnt]);
    }

  /* Store collation elements as map to collation class.  There are
     three kinds of symbols:
       - simple characters
       - collation elements
       - collation symbols
     We need to make a table which lets the user to access the primary
     weight based on the symbol string.  */
  symbols_hash_tab_size = next_prime ((4 * (charset->char_table.filled
					    + collate->elements.filled
					    + collate->symbols.filled)) / 3);
  symbols_hash_tab = obstack_alloc (&non_simple, (2 * symbols_hash_tab_size
						  * sizeof (uint32_t)));
  memset (symbols_hash_tab, '\377', (2 * symbols_hash_tab_size
				     * sizeof (uint32_t)));

  /* Now fill the array.  First the symbols from the character set,
     then the collation elements and last the collation symbols.  */
  hash_tab = &charset->char_table;
  while (1)
    {
      void *ptr;	/* Running pointer.  */
      const char *key;	/* Key for current bucket.  */
      size_t keylen;	/* Length of key data.  */
      void *data;	/* Data.  */

      ptr = NULL;
      while (iterate_table (hash_tab, &ptr, (const void **) &key,
			    &keylen, (void **) &data) == 0)
	{
	  size_t hash_val;
	  size_t idx;
	  uint32_t word;
	  unsigned int *weights;

	  if (hash_tab == &charset->char_table
	      || hash_tab == &collate->elements)
	    {
	      element_t *lastp, *firstp;
	      uint32_t dummy_name[2];
	      const uint32_t *name;
	      size_t name_len;

	      if (hash_tab == &charset->char_table)
		{
		  dummy_name[0] = (uint32_t) ((unsigned long int) data);
		  dummy_name[1] = L'\0';
		  name = dummy_name;
		  name_len = sizeof (uint32_t);
		}
	      else
		{
		  element_t *elemp = (element_t *) data;
		  name = elemp->name;
		  name_len = wcslen (name) * sizeof (uint32_t);
		}

	      /* First check whether this character is used at all.  */
	      if (find_entry (&collate->result, name, name_len,
			      (void *) &firstp) < 0)
		/* The symbol is not directly mentioned in the collation.
		   I.e., we use the value for UNDEFINED.  */
		lastp = &collate->undefined;
	      else
		{
		  /* The entry for the simple character is always found at
		     the end.  */
		  lastp = firstp;
		  while (lastp->next != NULL && wcscmp (name, lastp->name))
		    lastp = lastp->next;
		}

	      weights = lastp->ordering;
	    }
	  else
	    {
	      dummy_weights[0] = 1;
	      dummy_weights[collate->nrules]
		= (unsigned int) ((unsigned long int) data);

	      weights = dummy_weights;
	    }

	  /* In LASTP->ordering we now have the collation class.
	     Determine the place in the hashing table next.  */
	  hash_val = hash_string (key, keylen);
	  idx = hash_val % symbols_hash_tab_size;

	  if (symbols_hash_tab[2 * idx] != (~((uint32_t) 0)))
	    {
	      /* We need the second hashing function.  */
	      size_t c = 1 + (hash_val % (symbols_hash_tab_size - 2));

	      do
		if (idx >= symbols_hash_tab_size - c)
		  idx -= symbols_hash_tab_size - c;
		else
		  idx += c;
	      while (symbols_hash_tab[2 * idx] != (~((uint32_t) 0)));
	    }

	  symbols_hash_tab[2 * idx] = obstack_object_size (&string_pool);
	  symbols_hash_tab[2 * idx + 1] = (obstack_object_size (&non_simple)
					   / sizeof (uint32_t));

	  obstack_grow0 (&string_pool, key, keylen);
	  /* Adding the first weight looks complicated.  We have to deal
	     with the kind it is stored and with the fact that original
	     form uses `unsigned int's while we need `uint32_t' here.  */
	  word = weights[0];
	  obstack_grow (&non_simple, &word, sizeof (uint32_t));
	  for (cnt = 0; cnt < weights[0]; ++cnt)
	    {
	      word = weights[collate->nrules + cnt];
	      obstack_grow (&non_simple, &word, sizeof (uint32_t));
	    }
	}

      if (hash_tab == &charset->char_table)
	hash_tab = &collate->elements;
      else if (hash_tab == &collate->elements)
	hash_tab = &collate->symbols;
      else
	break;
    }

  /* Now we have the complete tables.  */
  if (obstack_object_size (&string_pool) % 4 != 0)
    obstack_blank (&non_simple, 4 - (obstack_object_size (&string_pool) % 4));
  symbols_string_pool_size = obstack_object_size (&string_pool);
  symbols_string_pool = obstack_finish (&string_pool);

  symbols_class_size = obstack_object_size (&non_simple);
  symbols_class = obstack_finish (&non_simple);

  /* Generate tables with other byte order.  */
  symbols_hash_tab_ob = obstack_alloc (&non_simple, (2 * symbols_hash_tab_size
						     * sizeof (uint32_t)));
  for (cnt = 0; cnt < 2 * symbols_hash_tab_size; ++cnt)
    symbols_hash_tab_ob[cnt] = bswap_32 (symbols_hash_tab[cnt]);

  symbols_class_ob = obstack_alloc (&non_simple, symbols_class_size);
  for (cnt = 0; cnt < symbols_class_size / 4; ++cnt)
    symbols_class_ob[cnt] = bswap_32 (symbols_class[cnt]);


  /* Store table addresses and lengths.   */
#if __BYTE_ORDER == __BIG_ENDIAN
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EB)].iov_base = table;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EB)].iov_len
    = table_best * level_best * entry_size * sizeof (table[0]);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EL)].iov_base = table2;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EL)].iov_len
    = table_best * level_best * entry_size * sizeof (table[0]);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EB)].iov_base = extra;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EB)].iov_len = extra_len;

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EL)].iov_base = extra2;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EL)].iov_len = extra_len;
#else
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EB)].iov_base = table2;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EB)].iov_len
    = table_best * level_best * entry_size * sizeof (table[0]);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EL)].iov_base = table;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_TABLE_EL)].iov_len
    = table_best * level_best * entry_size * sizeof (table[0]);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EB)].iov_base = extra2;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EB)].iov_len = extra_len;

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EL)].iov_base = extra;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_EXTRA_EL)].iov_len = extra_len;
#endif

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_UNDEFINED)].iov_base = &undefined_offset;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_UNDEFINED)].iov_len = sizeof (uint32_t);


  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_SIZE)].iov_base
    = &element_hash_tab_size;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_SIZE)].iov_len
    = sizeof (uint32_t);

#if __BYTE_ORDER == __BIG_ENDIAN
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EB)].iov_base
    = element_hash_tab;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EB)].iov_len
    = 2 * element_hash_tab_size * sizeof (uint32_t);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EL)].iov_base
    = element_hash_tab_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EL)].iov_len
    = 2 * element_hash_tab_size * sizeof (uint32_t);
#else
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EL)].iov_base
    = element_hash_tab;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EL)].iov_len
    = 2 * element_hash_tab_size * sizeof (uint32_t);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EB)].iov_base
    = element_hash_tab_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_HASH_EB)].iov_len
    = 2 * element_hash_tab_size * sizeof (uint32_t);
#endif

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_STR_POOL)].iov_base
    = element_string_pool;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_STR_POOL)].iov_len
    = element_string_pool_size;

#if __BYTE_ORDER == __BIG_ENDIAN
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EB)].iov_base
    = element_value;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EB)].iov_len
    = element_value_size;

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EL)].iov_base
    = element_value_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EL)].iov_len
    = element_value_size;
#else
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EL)].iov_base
    = element_value;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EL)].iov_len
    = element_value_size;

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EB)].iov_base
    = element_value_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_ELEM_VAL_EB)].iov_len
    = element_value_size;
#endif

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_SIZE)].iov_base
    = &symbols_hash_tab_size;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_SIZE)].iov_len
    = sizeof (uint32_t);

#if __BYTE_ORDER == __BIG_ENDIAN
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EB)].iov_base
    = symbols_hash_tab;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EB)].iov_len
    = 2 * symbols_hash_tab_size * sizeof (uint32_t);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EL)].iov_base
    = symbols_hash_tab_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EL)].iov_len
    = 2 * symbols_hash_tab_size * sizeof (uint32_t);
#else
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EL)].iov_base
    = symbols_hash_tab;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EL)].iov_len
    = 2 * symbols_hash_tab_size * sizeof (uint32_t);

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EB)].iov_base
    = symbols_hash_tab_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_HASH_EB)].iov_len
    = 2 * symbols_hash_tab_size * sizeof (uint32_t);
#endif

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_STR_POOL)].iov_base
    = symbols_string_pool;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_STR_POOL)].iov_len
    = symbols_string_pool_size;

#if __BYTE_ORDER == __BIG_ENDIAN
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EB)].iov_base
    = symbols_class;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EB)].iov_len
    = symbols_class_size;

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EL)].iov_base
    = symbols_class_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EL)].iov_len
    = symbols_class_size;
#else
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EL)].iov_base
    = symbols_class;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EL)].iov_len
    = symbols_class_size;

  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EB)].iov_base
    = symbols_class_ob;
  iov[2 + _NL_ITEM_INDEX (_NL_COLLATE_SYMB_CLASS_EB)].iov_len
    = symbols_class_size;
#endif

  /* Update idx array.  */
  idx[0] = iov[0].iov_len + iov[1].iov_len;
  for (cnt = 1; cnt < nelems; ++cnt)
    idx[cnt] = idx[cnt - 1] + iov[1 + cnt].iov_len;

  write_locale_data (output_path, "LC_COLLATE", 2 + nelems, iov);

  obstack_free (&non_simple, NULL);
  obstack_free (&string_pool, NULL);
}


static int
collate_element_to (struct linereader *ldfile,
		    struct locale_collate_t *collate,
		    struct token *code, struct charmap_t *charmap,
		    struct repertoire_t *repertoire)
{
  struct charseq *seq;
  uint32_t value;
  void *not_used;

  seq = charmap_find_value (charmap, code->val.str.start, code->val.str.len);
  if (seq != NULL)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates symbolic name in charmap"),
		(int) code->val.str.len, code->val.str.start);
      return 1;
    }

  value = repertoire_find_value (repertoire, code->val.str.start,
				 code->val.str.len);
  if (value != ILLEGAL_CHAR_VALUE)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates symbolic name in repertoire"),
		(int) code->val.str.len, code->val.str.start);
      return 1;
    }

  if (find_entry (&collate->elements, code->val.str.start, code->val.str.len,
		  &not_used) >= 0)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates other element definition"),
		(int) code->val.str.len, code->val.str.start);
      return 1;
    }

  if (find_entry (&collate->elements, code->val.str.start, code->val.str.len,
		  &not_used) >= 0)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates symbol definition"),
		(int) code->val.str.len, code->val.str.start);
      return 1;
    }

  return 0;
}


static void
collate_element_from (struct linereader *ldfile,
		      struct locale_collate_t *collate,
		      const char *to_str, struct token *code,
		      struct charmap_t *charmap,
		      struct repertoire_t *repertoire)
{
  element_t *elemp, *runp;

  /* CODE is a string.  */
  elemp = (element_t *) obstack_alloc (&collate->element_mem,
				       sizeof (element_t));

  /* We have to translate the string.  It may contain <...> character
     names.  */
  elemp->namemb = code->val.str.startmb;
  elemp->namewc = code->val.str.startwc;
  elemp->this_weight = 0;
  elemp->ordering = NULL;
  elemp->ordering_len = 0;

  if (elemp->namemb == NULL && elemp->namewc == NULL)
    {
      /* The string contains characters which are not in the charmap nor
	 in the repertoire.  Ignore the string.  */
      if (verbose)
	lr_error (ldfile, _("\
`from' string in collation element declaration contains unknown character"));
      return;
    }

  /* The entries in the linked lists of RESULT are sorting in
     descending order.  The order is important for the `strcoll' and
     `wcscoll' functions.  */
  if (find_entry (&collate->resultwc, elemp->namewc, sizeof (uint32_t),
		  (void *) &runp) >= 0)
    {
      /* We already have an entry with this key.  Check whether it is
	 identical.  */
      element_t *prevp = NULL;
      int cmpres;

      do
	{
	  cmpres = wcscmp (elemp->namewc, runp->namewc);
	  if (cmpres <= 0)
	    break;
	  prevp = runp;
	}
      while ((runp = runp->next) != NULL);

      if (cmpres == 0)
	lr_error (ldfile, _("\
duplicate collating element definition (repertoire)"));
      else
	{
	  elemp->next = runp;
	  if (prevp == NULL)
	    {
	      if (set_entry (&collate->resultwc, elemp->namewc,
			     sizeof (uint32_t), elemp) < 0)
		error (EXIT_FAILURE, 0, _("\
error while inserting collation element into hash table"));
	    }
	  else
	    prevp->next = elemp;
	}
    }
  else
    {
      elemp->next = NULL;
      if (insert_entry (&collate->resultwc, elemp->namewc, sizeof (uint32_t),
			elemp) < 0)
	error (EXIT_FAILURE, errno, _("error while inserting to hash table"));
    }

  /* Now also insert the element definition in the multibyte table.  */
  if (find_entry (&collate->resultmb, elemp->namemb, 1, (void *) &runp) >= 0)
    {
      /* We already have an entry with this key.  Check whether it is
	 identical.  */
      element_t *prevp = NULL;
      int cmpres;

      do
	{
	  cmpres = strcmp (elemp->namemb, runp->namemb);
	  if (cmpres <= 0)
	    break;
	  prevp = runp;
	}
      while ((runp = runp->next) != NULL);

      if (cmpres == 0)
	lr_error (ldfile, _("\
duplicate collating element definition (charmap)"));
      else
	{
	  elemp->next = runp;
	  if (prevp == NULL)
	    {
	      if (set_entry (&collate->resultmb, elemp->namemb, 1, elemp) < 0)
		error (EXIT_FAILURE, 0, _("\
error while inserting collation element into hash table"));
	    }
	  else
	    prevp->next = elemp;
	}
    }
  else
    {
      elemp->next = NULL;
      if (insert_entry (&collate->resultmb, elemp->namemb, 1, elemp) < 0)
	error (EXIT_FAILURE, errno, _("error while inserting to hash table"));
    }

  /* Finally install the mapping from the `to'-name to the `from'-name.  */
  if (insert_entry (&collate->elements, to_str, strlen (to_str),
		    (void *) elemp) < 0)
    lr_error (ldfile, _("cannot insert new collating symbol definition: %s"),
	      strerror (errno));
}


static void
collate_symbol (struct linereader *ldfile, struct locale_collate_t *collate,
		struct token *code, struct charmap_t *charmap,
		struct repertoire_t *repertoire)
{
  uint32_t value;
  struct charseq *seq;
  void *not_used;

  seq = charset_find_value (charmap, code->val.str.start, code->val.str.len);
  if (seq != NULL)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates symbolic name in charmap"),
		(int) code->val.str.len, code->val.str.start);
      return;
    }

  value = repertoire (repertoire, code->val.str.start, code->val.str.len);
  if (value != ILLEGAL_CHAR_VALUE)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates symbolic name in repertoire"),
		(int) code->val.str.len, code->val.str.start);
      return;
    }

  if (find_entry (&collate->elements, code->val.str.start, code->val.str.len,
		  &not_used) >= 0)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates element definition"),
		(int) code->val.str.len, code->val.str.start);
      return;
    }

  if (find_entry (&collate->symbols, code->val.str.start, code->val.str.len,
		  &not_used) >= 0)
    {
      lr_error (ldfile, _("symbol for multicharacter collating element "
		      "`%.*s' duplicates other symbol definition"),
		(int) code->val.str.len, code->val.str.start);
      return;
    }

  if (insert_entry (&collate->symbols, code->val.str.start, code->val.str.len,
		    (void *) 0) < 0)
    lr_error (ldfile, _("cannot insert new collating symbol definition: %s"),
	      strerror (errno));
}


void
collate_new_order (struct linereader *ldfile, struct localedef_t *locale,
		   enum coll_sort_rule sort_rule)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;

  if (collate->nrules >= collate->nrules_max)
    {
      collate->nrules_max *= 2;
      collate->rules
	= (enum coll_sort_rule *) xrealloc (collate->rules,
					    collate->nrules_max
					    * sizeof (enum coll_sort_rule));
    }

  collate->rules[collate->nrules++] = sort_rule;
}


void
collate_build_arrays (struct linereader *ldfile, struct localedef_t *locale)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;

  collate->rules
    = (enum coll_sort_rule *) xrealloc (collate->rules,
					collate->nrules
					* sizeof (enum coll_sort_rule));

  /* Allocate arrays for temporary weights.  */
  collate->weight_cnt = (int *) xmalloc (collate->nrules * sizeof (int));

  /* Choose arbitrary start value for table size.  */
  collate->nweight_max = 5 * collate->nrules;
  collate->weight = (int *) xmalloc (collate->nweight_max * sizeof (int));
}


int
collate_order_elem (struct linereader *ldfile, struct localedef_t *locale,
		    struct token *code, struct charset_t *charset)
{
  const uint32_t zero = L'\0';
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;
  int result = 0;
  uint32_t value;
  void *tmp;
  unsigned int i;

  switch (code->tok)
    {
    case tok_bsymbol:
      /* We have a string to find in one of the three hashing tables.  */
      value = charset_find_value (&charset->char_table, code->val.str.start,
				  code->val.str.len);
      if (value != ILLEGAL_CHAR_VALUE)
	{
	  element_t *lastp, *firstp;

	  collate->kind = character;

	  if (find_entry (&collate->result, &value, sizeof (uint32_t),
			  (void *) &firstp) < 0)
	    firstp = lastp = NULL;
	  else
	    {
	      /* The entry for the simple character is always found at
		 the end.  */
	      lastp = firstp;
	      while (lastp->next != NULL)
		lastp = lastp->next;

	      if (lastp->name[0] == value && lastp->name[1] == L'\0')
		{
		  lr_error (ldfile,
			    _("duplicate definition for character `%.*s'"),
			    (int) code->val.str.len, code->val.str.start);
		  lr_ignore_rest (ldfile, 0);
		  result = -1;
		  break;
		}
	    }

	  collate->current_element
	    = (element_t *) obstack_alloc (&collate->element_mem,
					   sizeof (element_t));

	  obstack_grow (&collate->element_mem, &value, sizeof (value));
	  obstack_grow (&collate->element_mem, &zero, sizeof (zero));

	  collate->current_element->name =
	    (const uint32_t *) obstack_finish (&collate->element_mem);

	  collate->current_element->this_weight = ++collate->order_cnt;

	  collate->current_element->next = NULL;

	  if (firstp == NULL)
	    {
	      if (insert_entry (&collate->result, &value, sizeof (uint32_t),
				(void *) collate->current_element) < 0)
		{
		  lr_error (ldfile, _("cannot insert collation element `%.*s'"),
			    (int) code->val.str.len, code->val.str.start);
		  exit (4);
		}
	    }
	  else
	    lastp->next = collate->current_element;
	}
      else if (find_entry (&collate->elements, code->val.str.start,
			   code->val.str.len, &tmp) >= 0)
	{
	  collate->current_element = (element_t *) tmp;

	  if (collate->current_element->this_weight != 0)
	    {
	      lr_error (ldfile, _("\
collation element `%.*s' appears more than once: ignore line"),
			(int) code->val.str.len, code->val.str.start);
	      lr_ignore_rest (ldfile, 0);
	      result = -1;
	      break;
	    }

	  collate->kind = element;
	  collate->current_element->this_weight = ++collate->order_cnt;
	}
      else if (find_entry (&collate->symbols, code->val.str.start,
			   code->val.str.len, &tmp) >= 0)
	{
	  unsigned int order = ++collate->order_cnt;

	  if ((unsigned long int) tmp != 0ul)
	    {
	      lr_error (ldfile, _("\
collation symbol `%.*s' appears more than once: ignore line"),
			(int) code->val.str.len, code->val.str.start);
	      lr_ignore_rest (ldfile, 0);
	      result = -1;
	      break;
	    }

	  collate->kind = symbol;

	  if (set_entry (&collate->symbols, code->val.str.start,
			 code->val.str.len, (void *) order) < 0)
	    {
	      lr_error (ldfile, _("cannot process order specification"));
	      exit (4);
	    }
	}
      else
	{
	  if (verbose)
	    lr_error (ldfile, _("unknown symbol `%.*s': line ignored"),
		      (int) code->val.str.len, code->val.str.start);
          lr_ignore_rest (ldfile, 0);

          result = -1;
	}
      break;

    case tok_undefined:
      collate->kind = undefined;
      collate->current_element = &collate->undefined;
      break;

    case tok_ellipsis:
      if (collate->was_ellipsis)
	{
	  lr_error (ldfile, _("\
two lines in a row containing `...' are not allowed"));
	  result = -1;
	}
      else if (collate->kind != character)
	{
	  /* An ellipsis requires the previous line to be an
	     character definition.  */
	  lr_error (ldfile, _("\
line before ellipsis does not contain definition for character constant"));
	  lr_ignore_rest (ldfile, 0);
	  result = -1;
	}
      else
	collate->kind = ellipsis;
      break;

    default:
      assert (! "illegal token in `collate_order_elem'");
    }

  /* Now it's time to handle the ellipsis in the previous line.  We do
     this only when the last line contained an definition for a
     character, the current line also defines an character, the
     character code for the later is bigger than the former.  */
  if (collate->was_ellipsis)
    {
      if (collate->kind != character)
	{
	  lr_error (ldfile, _("\
line after ellipsis must contain character definition"));
	  lr_ignore_rest (ldfile, 0);
	  result = -1;
	}
      else if (collate->last_char > value)
	{
	  lr_error (ldfile, _("end point of ellipsis range is bigger then start"));
	  lr_ignore_rest (ldfile, 0);
	  result = -1;
	}
      else
	{
	  /* We can fill the arrays with the information we need.  */
	  uint32_t name[2];
	  unsigned int *data;
	  size_t *ptr;
	  size_t cnt;

	  name[0] = collate->last_char + 1;
	  name[1] = L'\0';

	  data = (unsigned int *) alloca ((collate->nrules + collate->nweight)
					  * sizeof (unsigned int));
	  ptr = (size_t *) alloca (collate->nrules * sizeof (size_t));

	  /* Prepare data.  Because the characters covered by an
	     ellipsis all have equal values we prepare the data once
	     and only change the variable number (if there are any).
	     PTR[...] will point to the entries which will have to be
	     fixed during the output loop.  */
	  for (cnt = 0; cnt < collate->nrules; ++cnt)
	    {
	      data[cnt] = collate->weight_cnt[cnt];
	      ptr[cnt] = (cnt == 0
			  ? collate->nweight
			  : ptr[cnt - 1] + collate->weight_cnt[cnt - 1]);
	    }

	  for (cnt = 0; cnt < collate->nweight; ++cnt)
	    data[collate->nrules + cnt] = collate->weight[cnt];

	  for (cnt = 0; cnt < collate->nrules; ++cnt)
	    if ((uint32_t) data[ptr[cnt]] != ELLIPSIS_CHAR)
	      ptr[cnt] = 0;

	  while (name[0] <= value)
	    {
	      element_t *pelem;

	      pelem = (element_t *) obstack_alloc (&collate->element_mem,
						   sizeof (element_t));
	      pelem->name
		= (const uint32_t *) obstack_copy (&collate->element_mem,
						  name, 2 * sizeof (uint32_t));
	      pelem->this_weight = ++collate->order_cnt;

	      pelem->ordering_len = collate->nweight;
	      pelem->ordering
		= (unsigned int *) obstack_copy (&collate->element_mem, data,
						 (collate->nrules
						  + pelem->ordering_len)
						 * sizeof (unsigned int));

	      /* `...' weights need to be adjusted.  */
	      for (cnt = 0; cnt < collate->nrules; ++cnt)
		if (ptr[cnt] != 0)
		  pelem->ordering[ptr[cnt]] = pelem->this_weight;

	      /* Insert new entry into result table.  */
	      if (find_entry (&collate->result, name, sizeof (uint32_t),
			      (void *) &pelem->next) >= 0)
		{
		  if (set_entry (&collate->result, name, sizeof (uint32_t),
				 (void *) pelem) < 0)
		    error (4, 0, _("cannot insert into result table"));
		}
	      else
		{
		  pelem->next = NULL;
		  if (insert_entry (&collate->result, name, sizeof (uint32_t),
				    (void *) pelem) < 0)
		    error (4, 0, _("cannot insert into result table"));
		}

	      /* Increment counter.  */
	      ++name[0];
	    }
	}
    }

  /* Reset counters for weights.  */
  collate->weight_idx = 0;
  collate->nweight = 0;
  for (i = 0; i < collate->nrules; ++i)
    collate->weight_cnt[i] = 0;
  collate->current_patch = NULL;

  return result;
}


int
collate_weight_bsymbol (struct linereader *ldfile, struct localedef_t *locale,
			struct token *code, struct charset_t *charset)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;
  unsigned int here_weight;
  uint32_t value;
  void *tmp;

  assert (code->tok == tok_bsymbol);

  value = charset_find_value (&charset->char_table, code->val.str.start,
			      code->val.str.len);
  if (value != ILLEGAL_CHAR_VALUE)
    {
      element_t *runp;

      if (find_entry (&collate->result, &value, sizeof (uint32_t),
		      (void *)&runp) < 0)
	runp = NULL;

      while (runp != NULL
	     && (runp->name[0] != value || runp->name[1] != L'\0'))
	runp = runp->next;

      here_weight = runp == NULL ? 0 : runp->this_weight;
    }
  else if (find_entry (&collate->elements, code->val.str.start,
		       code->val.str.len, &tmp) >= 0)
    {
      element_t *runp = (element_t *) tmp;

      here_weight = runp->this_weight;
    }
  else if (find_entry (&collate->symbols, code->val.str.start,
		       code->val.str.len, &tmp) >= 0)
    {
      here_weight = (unsigned int) tmp;
    }
  else
    {
      if (verbose)
	lr_error (ldfile, _("unknown symbol `%.*s': line ignored"),
		  (int) code->val.str.len, code->val.str.start);
      lr_ignore_rest (ldfile, 0);
      return -1;
    }

  /* When we currently work on a collation symbol we do not expect any
     weight.  */
  if (collate->kind == symbol)
    {
      lr_error (ldfile, _("\
specification of sorting weight for collation symbol does not make sense"));
      lr_ignore_rest (ldfile, 0);
      return -1;
    }

  /* Add to the current collection of weights.  */
  if (collate->nweight >= collate->nweight_max)
    {
      collate->nweight_max *= 2;
      collate->weight = (unsigned int *) xrealloc (collate->weight,
						   collate->nweight_max);
    }

  /* If the weight is currently not known, we remember to patch the
     resulting tables.  */
  if (here_weight == 0)
    {
      patch_t *newp;

      newp = (patch_t *) obstack_alloc (&collate->element_mem,
					sizeof (patch_t));
      newp->fname = ldfile->fname;
      newp->lineno = ldfile->lineno;
      newp->token = (const char *) obstack_copy0 (&collate->element_mem,
						  code->val.str.start,
						  code->val.str.len);
      newp->where.idx = collate->nweight++;
      newp->next = collate->current_patch;
      collate->current_patch = newp;
    }
  else
    collate->weight[collate->nweight++] = here_weight;
  ++collate->weight_cnt[collate->weight_idx];

  return 0;
}


int
collate_next_weight (struct linereader *ldfile, struct localedef_t *locale)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;

  if (collate->kind == symbol)
    {
      lr_error (ldfile, _("\
specification of sorting weight for collation symbol does not make sense"));
      lr_ignore_rest (ldfile, 0);
      return -1;
    }

  ++collate->weight_idx;
  if (collate->weight_idx >= collate->nrules)
    {
      lr_error (ldfile, _("too many weights"));
      lr_ignore_rest (ldfile, 0);
      return -1;
    }

  return 0;
}


int
collate_simple_weight (struct linereader *ldfile, struct localedef_t *locale,
		       struct token *code, struct charset_t *charset)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;
  unsigned int value = 0;

  /* There current tokens can be `IGNORE', `...', or a string.  */
  switch (code->tok)
    {
    case tok_ignore:
      /* This token is allowed in all situations.  */
      value = IGNORE_CHAR;
      break;

    case tok_ellipsis:
      /* The ellipsis is only allowed for the `...' or `UNDEFINED'
	 entry.  */
      if (collate->kind != ellipsis && collate->kind != undefined)
	{
	  lr_error (ldfile, _("\
`...' must only be used in `...' and `UNDEFINED' entries"));
	  lr_ignore_rest (ldfile, 0);
	  return -1;
	}
      value = ELLIPSIS_CHAR;
      break;

    case tok_string:
      /* This can become difficult.  We have to get the weights which
	 correspond to the single wide chars in the string.  But some
	 of the `chars' might not be real characters, but collation
	 elements or symbols.  And so the string decoder might have
	 signaled errors.  The string at this point is not translated.
	 I.e., all <...> sequences are still there.  */
      {
	char *runp = code->val.str.start;
	void *tmp;

	while (*runp != '\0')
	  {
	    char *startp = (char *) runp;
	    char *putp = (char *) runp;
	    uint32_t wch;

	    /* Lookup weight for char and store it.  */
	    if (*runp == '<')
	      {
		while (*++runp != '\0' && *runp != '>')
		  {
		    if (*runp == ldfile->escape_char)
		      if (*++runp == '\0')
			{
			  lr_error (ldfile, _("unterminated weight name"));
			  lr_ignore_rest (ldfile, 0);
			  return -1;
			}
		    *putp++ = *runp;
		  }
		if (*runp == '>')
		  ++runp;

		if (putp == startp)
		  {
		    lr_error (ldfile, _("empty weight name: line ignored"));
		    lr_ignore_rest (ldfile, 0);
		    return -1;
		  }

		wch = charset_find_value (&charset->char_table, startp,
					  putp - startp);
		if (wch != ILLEGAL_CHAR_VALUE)
		  {
		    element_t *pelem;

		    if (find_entry (&collate->result, &wch, sizeof (uint32_t),
				    (void *)&pelem) < 0)
		      pelem = NULL;

		    while (pelem != NULL
			   && (pelem->name[0] != wch
			       || pelem->name[1] != L'\0'))
		      pelem = pelem->next;

		    value = pelem == NULL ? 0 : pelem->this_weight;
		  }
		else if (find_entry (&collate->elements, startp, putp - startp,
				     &tmp) >= 0)
		  {
		    element_t *pelem = (element_t *) tmp;

		    value = pelem->this_weight;
		  }
		else if (find_entry (&collate->symbols, startp, putp - startp,
				     &tmp) >= 0)
		  {
		    value = (unsigned int) tmp;
		  }
		else
		  {
		    if (verbose)
		      lr_error (ldfile, _("unknown symbol `%.*s': line ignored"),
				(int) (putp - startp), startp);
		    lr_ignore_rest (ldfile, 0);
		    return -1;
		  }
	      }
	    else
	      {
		element_t *wp;
		uint32_t wch;

		if (*runp == ldfile->escape_char)
		  {
		    static const char digits[] = "0123456789abcdef";
		    const char *dp;
		    int base;

		    ++runp;
		    if (tolower (*runp) == 'x')
		      {
			++runp;
			base = 16;
		      }
		    else if (tolower (*runp) == 'd')
		      {
			++runp;
			base = 10;
		      }
		    else
		      base = 8;

		    dp = strchr (digits, tolower (*runp));
		    if (dp == NULL || (dp - digits) >= base)
		      {
		      illegal_char:
			lr_error (ldfile, _("\
illegal character constant in string"));
			lr_ignore_rest (ldfile, 0);
			return -1;
		      }
		    wch = dp - digits;
		    ++runp;

		    dp = strchr (digits, tolower (*runp));
		    if (dp == NULL || (dp - digits) >= base)
		      goto illegal_char;
		    wch *= base;
		    wch += dp - digits;
		    ++runp;

		    if (base != 16)
		      {
			dp = strchr (digits, tolower (*runp));
			if (dp != NULL && (dp - digits < base))
			  {
			    wch *= base;
			    wch += dp - digits;
			    ++runp;
			  }
		      }
		  }
		else
		  wch = (uint32_t) *runp++;

		/* Lookup the weight for WCH.  */
		if (find_entry (&collate->result, &wch, sizeof (wch),
				(void *)&wp) < 0)
		  wp = NULL;

		while (wp != NULL
		       && (wp->name[0] != wch || wp->name[1] != L'\0'))
		  wp = wp->next;

		value = wp == NULL ? 0 : wp->this_weight;

		/* To get the correct name for the error message.  */
		putp = runp;

		/**************************************************\
		|* I know here is something wrong.  Characters in *|
		|* the string which are not in the <...> form	  *|
		|* cannot be declared forward for now!!!	  *|
		\**************************************************/
	      }

	    /* Store in weight array.  */
	    if (collate->nweight >= collate->nweight_max)
	      {
		collate->nweight_max *= 2;
		collate->weight
		  = (unsigned int *) xrealloc (collate->weight,
					       collate->nweight_max);
	      }

	    if (value == 0)
	      {
		patch_t *newp;

		newp = (patch_t *) obstack_alloc (&collate->element_mem,
						  sizeof (patch_t));
		newp->fname = ldfile->fname;
		newp->lineno = ldfile->lineno;
		newp->token
		  = (const char *) obstack_copy0 (&collate->element_mem,
						  startp, putp - startp);
		newp->where.idx = collate->nweight++;
		newp->next = collate->current_patch;
		collate->current_patch = newp;
	      }
	    else
	      collate->weight[collate->nweight++] = value;
	    ++collate->weight_cnt[collate->weight_idx];
	  }
      }
      return 0;

    default:
      assert (! "should not happen");
    }


  if (collate->nweight >= collate->nweight_max)
    {
      collate->nweight_max *= 2;
      collate->weight = (unsigned int *) xrealloc (collate->weight,
						   collate->nweight_max);
    }

  collate->weight[collate->nweight++] = value;
  ++collate->weight_cnt[collate->weight_idx];

  return 0;
}


void
collate_end_weight (struct linereader *ldfile, struct localedef_t *locale)
{
  struct locale_collate_t *collate = locale->categories[LC_COLLATE].collate;
  element_t *pelem = collate->current_element;

  if (collate->kind == symbol)
    {
      /* We don't have to do anything.  */
      collate->was_ellipsis = 0;
      return;
    }

  if (collate->kind == ellipsis)
    {
      /* Before the next line is processed the ellipsis is handled.  */
      collate->was_ellipsis = 1;
      return;
    }

  assert (collate->kind == character || collate->kind == element
	  || collate->kind == undefined);

  /* Fill in the missing weights.  */
  while (++collate->weight_idx < collate->nrules)
    {
      collate->weight[collate->nweight++] = pelem->this_weight;
      ++collate->weight_cnt[collate->weight_idx];
    }

  /* Now we know how many ordering weights the current
     character/element has.  Allocate room in the element structure
     and copy information.  */
  pelem->ordering_len = collate->nweight;

  /* First we write an array with the number of values for each
     weight.  */
  obstack_grow (&collate->element_mem, collate->weight_cnt,
		collate->nrules * sizeof (unsigned int));

  /* Now the weights itselves.  */
  obstack_grow (&collate->element_mem, collate->weight,
		collate->nweight * sizeof (unsigned int));

  /* Get result.  */
  pelem->ordering = obstack_finish (&collate->element_mem);

  /* Now we handle the "patches".  */
  while (collate->current_patch != NULL)
    {
      patch_t *this_patch;

      this_patch = collate->current_patch;

      this_patch->where.pos = &pelem->ordering[collate->nrules
					      + this_patch->where.idx];

      collate->current_patch = this_patch->next;
      this_patch->next = collate->all_patches;
      collate->all_patches = this_patch;
    }

  /* Set information for next round.  */
  collate->was_ellipsis = 0;
  if (collate->kind != undefined)
    collate->last_char = pelem->name[0];
}


/* The parser for the LC_CTYPE section of the locale definition.  */
void
read_lc_collate (struct linereader *ldfile, struct localedef_t *result,
		 struct charmap_t *charmap, struct repertoire_t *repertoire,
		 int ignore_content)
{
  struct locale_collate_t *collate;
  int did_copy = 0;
  const char *save_str;

  /* The rest of the line containing `LC_COLLATE' must be free.  */
  lr_ignore_rest (ldfile, 1);

  now = lr_token (ldfile, charmap, NULL);
  nowtok = now->tok;

  /* If we see `copy' now we are almost done.  */
  if (nowtok == tok_copy)
    {
      handle_copy (ldfile, charmap, repertoire, result, tok_lc_collate,
		   LC_COLLATE, "LC_COLLATE", ignore_content);
      did_copy = 1;
    }

  /* Prepare the data structures.  */
  collate_startup (ldfile, result, charmap, ignore_content);
  collate = result->categories[LC_COLLATE].collate;

  while (1)
    {
      /* Of course we don't proceed beyond the end of file.  */
      if (nowtok == tok_eof)
        break;

      /* Ignore empty lines.  */
      if (nowtok == tok_eol)
        {
          now = lr_token (ldfile, charmap, NULL);
          nowtok = now->tok;
          continue;
        }

      switch (nowtok)
        {
	case tok_coll_weight_max:
	  if (did_copy)
	    goto err_label;
	  /* The rest of the line must be a single integer value.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok != tok_number)
	    goto err_label;
	  /* We simply forget about the value we just read, the implementation
	     has no fixed limits.  */
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_script:
	  if (did_copy)
	    goto err_label;
	  /* We expect the name of the script in brackets.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok != tok_bsymbol && now->tok != tok_ucs4)
	    goto err_label;
	  if (now->tok != tok_bsymbol)
	    {
	      lr_error (ldfile, _("\
script name `%s' must not duplicate any known name"),
			tok->val.str.startmb);
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }
	  collate->scripts = xmalloc (collate->scripts,
				      (collate->nscripts
				       * sizeof (const char *)));
	  collate->scripts[collate->nscripts++] = tok->val.str.startmb;
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_collating_element:
	  if (did_copy)
	    goto err_label;
	  /* Get the first argument, a symbol in brackets.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok != tok_bsymbol)
	    goto err_label;
	  /* Test it.  */
	  if (collate_element_to (ldfile, collate, now, charmap, repertoire))
	    {
	      /* An error occurred.  */
	      lr_ignore_rest (ldfile, 0);
	      break;
	    }
	  save_str = tok->val.str.startmb;
	  /* Next comes `from'.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok != tok_from)
	    goto err_label;
	  /* Now comes a string.  */
	  now = lr_token (ldfile, charmap, repertoire);
	  if (now->tok != tok_string)
	    goto err_label;
	  collate_element_from (ldfile, collate, save_str, now, charmap,
				repertoire);
	  /* The rest of the line should be empty.  */
	  lr_ignore_rest (ldfile, 1);
	  break;

	case tok_collating_symbol:
	  if (did_copy)
	    goto err_label;
	  /* Get the argument, a single symbol in brackets.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok != tok_bsymbol)
	    goto err_label;
	  collate_symbol (ldfile, collate, now, charmap, repertoire);
	  break;

	case tok_order_start:
	  if (did_copy)
	    goto err_label;

	  /* We expect now a scripting symbol or start right away
	     with the order keywords.  Or we have no argument at all
	     in which means `forward'.  */
	  now = lr_token (ldfile, charmap, NULL);
	  if (now->tok == tok_eol)
	    {
	      static enum coll_sort_rule default_rule = sort_forward;
	      /* Use a single `forward' rule.  */
	      collate->nrules = 1;
	      collate->rules = &default_rule;
	    }
	  else
	    {
	      /* XXX We don't recognize the ISO 14651 extensions yet.  */
	      uint32_t nrules = 0;
	      uint32_t nrules_max = 32;
	      enum coll_sort_rule *rules = alloca (nrules_max
						   * sizeof (*rules));
	      int saw_semicolon = 0;

	      memset (rules, '\0', nrules_max * sizeof (*rules));
	      do
		{
		  if (now->tok != tok_forward && now->tok != tok_backward
		      && now->tok != tok_position)
		    goto err_label;

		  if (saw_semicolon)
		    {
		      if (nrules == nrules_max)
			{
			  newp = alloca (nrules_max * 2 * sizeof (*rules));
			  rules = memcpy (newp, rules,
					  nrules_max * sizeof (*rules));
			  memset (&rules[nrules_max], '\0',
				  nrules_max * sizeof (*rules));
			  nrules_max *= 2;
			}
		      ++nrules;
		    }

		  switch (now->tok)
		    {
		    case tok_forward:
		      if ((rules[nrules] & sort_backward) != 0)
			{
			  lr_error (ldfile, _("\
`forward' and `backward' order exclude each other"));
			  lr_ignore_rest (ldfile, 0);
			  goto error_sort;
			}
		      rules[nrules] |= sort_forward;
		      break;
		    case tok_backward:
		      if ((rules[nrules] & sort_forward) != 0)
			{
			  lr_error (ldfile, _("\
`forward' and `backward' order exclude each other"));
			  lr_ignore_rest (ldfile, 0);
			  goto error_sort;
			}
		      rules[nrules] |= sort_backward;
		      break;
		    case tok_position:
		      rules[nrules] |= tok_position;
		      break;
		    }

		  /* Get the next token.  This is either the end of the line,
		     a comma or a semicolon.  */
		  now = lr_token (ldfile, charmap, NULL);
		  if (now->tok == tok_comma || now->tok == tok_semicolon)
		    {
		      saw_semicolon = now->tok == tok_semicolon;
		      now = lr_token (ldfile, charmap, NULL);
		    }
		}
	      while (now->tok != tok_eol || now->tok != tok_eof);

	    error_sort:
	      collate->nrules = nrules;
	      collate->rules = memcpy (xmalloc (nrules * sizeof (*rules)),
				       rules, nrules * sizeof (*rules));
	    }

	  /* Now read the rules.  */
	  read_rules (ldfile, collate, charmap, repertoire);
	  break;

	case tok_reorder_after:
	  break;

	case tok_reorder_script_after:
	  break;

        default:
        err_label:
          if (now->tok != tok_eof)
            SYNTAX_ERROR (_("syntax error in %s locale definition"),
                          "LC_COLLATE");
	}

      /* Prepare for the next round.  */
      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }

  /* When we come here we reached the end of the file.  */
  lr_error (ldfile, _("premature end of file while reading category `%s'"),
            "LC_COLLATE");
}

#endif
