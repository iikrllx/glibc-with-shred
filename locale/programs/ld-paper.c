/* Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <byteswap.h>
#include <error.h>
#include <langinfo.h>
#include <string.h>
#include <sys/uio.h>

#include <assert.h>

#include "localeinfo.h"
#include "locfile.h"


/* The real definition of the struct for the LC_PAPER locale.  */
struct locale_paper_t
{
  uint32_t height;
  uint32_t height_ob;
  uint32_t width;
  uint32_t width_ob;
};


static void
paper_startup (struct linereader *lr, struct localedef_t *locale,
	       int ignore_content)
{
  if (!ignore_content)
    locale->categories[LC_PAPER].paper =
      (struct locale_paper_t *) xcalloc (1, sizeof (struct locale_paper_t));

  lr->translate_strings = 1;
  lr->return_widestr = 0;
}


void
paper_finish (struct localedef_t *locale, struct charmap_t *charmap)
{
  struct locale_paper_t *paper = locale->categories[LC_PAPER].paper;

  if (paper->height == 0)
    {
      error (0, 0, _("%s: field `%s' not defined"), "LC_PAPER", "height");
      /* Use as default values the values from the i18n locale.  */
      paper->height = 297;
    }
  paper->height_ob = bswap_32 (paper->height);

  if (paper->width == 0)
    {
      error (0, 0, _("%s: field `%s' not defined"), "LC_PAPER", "width");
      /* Use as default values the values from the i18n locale.  */
      paper->width = 210;
    }
  paper->width_ob = bswap_32 (paper->width);
}


void
paper_output (struct localedef_t *locale, struct charmap_t *charmap,
	      const char *output_path)
{
  struct locale_paper_t *paper = locale->categories[LC_PAPER].paper;
  struct iovec iov[2 + _NL_ITEM_INDEX (_NL_NUM_LC_PAPER)];
  struct locale_file data;
  uint32_t idx[_NL_ITEM_INDEX (_NL_NUM_LC_PAPER)];
  size_t cnt = 0;

  data.magic = LIMAGIC (LC_PAPER);
  data.n = _NL_ITEM_INDEX (_NL_NUM_LC_PAPER);
  iov[cnt].iov_base = (void *) &data;
  iov[cnt].iov_len = sizeof (data);
  ++cnt;

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define height_eb	height_ob
# define height_el	height
# define width_eb	width_ob
# define width_el	width
#else
# define height_eb	height
# define height_el	height_ob
# define width_eb	width
# define width_el	width_ob
#endif

  iov[cnt].iov_base = (void *) idx;
  iov[cnt].iov_len = sizeof (idx);
  ++cnt;

  idx[cnt - 2] = iov[0].iov_len + iov[1].iov_len;
  iov[cnt].iov_base = &paper->height_eb;
  iov[cnt].iov_len = 4;
  ++cnt;

  idx[cnt - 2] = iov[0].iov_len + iov[1].iov_len;
  iov[cnt].iov_base = &paper->height_el;
  iov[cnt].iov_len = 4;
  ++cnt;

  idx[cnt - 2] = iov[0].iov_len + iov[1].iov_len;
  iov[cnt].iov_base = &paper->width_eb;
  iov[cnt].iov_len = 4;
  ++cnt;

  idx[cnt - 2] = iov[0].iov_len + iov[1].iov_len;
  iov[cnt].iov_base = &paper->width_el;
  iov[cnt].iov_len = 4;
  ++cnt;

  assert (cnt == 2 + _NL_ITEM_INDEX (_NL_NUM_LC_PAPER));

  write_locale_data (output_path, "LC_PAPER",
		     2 + _NL_ITEM_INDEX (_NL_NUM_LC_PAPER), iov);
}


/* The parser for the LC_PAPER section of the locale definition.  */
void
paper_read (struct linereader *ldfile, struct localedef_t *result,
	    struct charmap_t *charmap, const char *repertoire_name,
	    int ignore_content)
{
  struct repertoire_t *repertoire = NULL;
  struct locale_paper_t *paper;
  struct token *now;
  struct token *arg;
  enum token_t nowtok;

  /* Get the repertoire we have to use.  */
  if (repertoire_name != NULL)
    repertoire = repertoire_read (repertoire_name);

  /* The rest of the line containing `LC_PAPER' must be empty.  */
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
      handle_copy (ldfile, charmap, repertoire, tok_lc_paper, LC_PAPER,
		   "LC_PAPER", ignore_content);
      return;
    }

  /* Prepare the data structures.  */
  paper_startup (ldfile, result, ignore_content);
  paper = result->categories[LC_PAPER].paper;

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
#define INT_ELEM(cat) \
	case tok_##cat:							      \
	  arg = lr_token (ldfile, charmap, NULL);			      \
	  if (arg->tok != tok_number)					      \
	    goto err_label;						      \
	  else if (paper->cat != 0)					      \
	    lr_error (ldfile, _("%s: field `%s' declared more than once"),    \
		      "LC_PAPER", #cat);				      \
	  else if (!ignore_content)					      \
	    paper->cat = arg->val.num;					      \
	  break

	  INT_ELEM (height);
	  INT_ELEM (width);

	case tok_end:
	  /* Next we assume `LC_PAPER'.  */
	  arg = lr_token (ldfile, charmap, NULL);
	  if (arg->tok == tok_eof)
	    break;
	  if (arg->tok == tok_eol)
	    lr_error (ldfile, _("%s: incomplete `END' line"), "LC_PAPER");
	  else if (arg->tok != tok_lc_paper)
	    lr_error (ldfile, _("\
%1$s: definition does not end with `END %1$s'"), "LC_PAPER");
	  lr_ignore_rest (ldfile, arg->tok == tok_lc_paper);
	  return;

	default:
	err_label:
	  SYNTAX_ERROR (_("%s: syntax error"), "LC_PAPER");
	}

      /* Prepare for the next round.  */
      now = lr_token (ldfile, charmap, NULL);
      nowtok = now->tok;
    }

  /* When we come here we reached the end of the file.  */
  lr_error (ldfile, _("%s: premature end of file"), "LC_PAPER");
}
