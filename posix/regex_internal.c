/* Extended regular expression matching and search library.
   Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.

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

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#ifdef _LIBC
# ifndef _RE_DEFINE_LOCALE_FUNCTIONS
#  define _RE_DEFINE_LOCALE_FUNCTIONS 1
#  include <locale/localeinfo.h>
#  include <locale/elem-hash.h>
#  include <locale/coll-lookup.h>
# endif
#endif

/* This is for other GNU distributions with internationalized messages.  */
#if HAVE_LIBINTL_H || defined _LIBC
# include <libintl.h>
# ifdef _LIBC
#  undef gettext
#  define gettext(msgid) __dcgettext ("libc", msgid, LC_MESSAGES)
# endif
#else
# define gettext(msgid) (msgid)
#endif

#ifndef gettext_noop
/* This define is so xgettext can find the internationalizable
   strings.  */
# define gettext_noop(String) String
#endif

#include "regex.h"
#include "regex_internal.h"

static void re_string_construct_common (const unsigned char *str,
                                        int len, re_string_t *pstr);
#ifdef RE_ENABLE_I18N
static reg_errcode_t build_wcs_buffer (re_string_t *pstr);
static reg_errcode_t build_wcs_upper_buffer (re_string_t *pstr);
#endif /* RE_ENABLE_I18N */
static reg_errcode_t build_upper_buffer (re_string_t *pstr);
static reg_errcode_t re_string_translate_buffer (re_string_t *pstr,
						 RE_TRANSLATE_TYPE trans);
static re_dfastate_t *create_newstate_common (re_dfa_t *dfa,
                                              const re_node_set *nodes,
                                              unsigned int hash);
static re_dfastate_t *create_ci_newstate (re_dfa_t *dfa,
                                          const re_node_set *nodes,
                                          unsigned int hash);
static re_dfastate_t *create_cd_newstate (re_dfa_t *dfa,
                                          const re_node_set *nodes,
                                          unsigned int context,
                                          unsigned int hash);
static unsigned int inline calc_state_hash (const re_node_set *nodes,
                                            unsigned int context);

/* Functions for string operation.  */

/* Construct string object.  */
static reg_errcode_t
re_string_construct (pstr, str, len, trans)
     re_string_t *pstr;
     const unsigned char *str;
     int len;
     RE_TRANSLATE_TYPE trans;
{
  reg_errcode_t ret;
  re_string_construct_common (str, len, pstr);
#ifdef RE_ENABLE_I18N
  if (MB_CUR_MAX >1 && pstr->len > 0)
    {
      ret = build_wcs_buffer (pstr);
      if (ret != REG_NOERROR)
        return ret;
    }
#endif /* RE_ENABLE_I18N  */
  pstr->mbs_case = str;
  if (trans != NULL)
    {
      ret = re_string_translate_buffer (pstr, trans);
      if (ret != REG_NOERROR)
        return ret;
    }
  return REG_NOERROR;
}

/* Construct string object. We use this function instead of
   re_string_construct for case insensitive mode.  */

static reg_errcode_t
re_string_construct_toupper (pstr, str, len, trans)
     re_string_t *pstr;
     const unsigned char *str;
     int len;
     RE_TRANSLATE_TYPE trans;
{
  reg_errcode_t ret;
  /* Set case sensitive buffer.  */
  re_string_construct_common (str, len, pstr);
#ifdef RE_ENABLE_I18N
  if (MB_CUR_MAX >1)
    {
      if (pstr->len > 0)
        {
          ret = build_wcs_upper_buffer (pstr);
          if (ret != REG_NOERROR)
            return ret;
        }
    }
  else
#endif /* RE_ENABLE_I18N  */
    {
      if (pstr->len > 0)
        {
          ret = build_upper_buffer (pstr);
          if (ret != REG_NOERROR)
            return ret;
        }
    }
  pstr->mbs_case = str;
  if (trans != NULL)
    {
      ret = re_string_translate_buffer (pstr, trans);
      if (ret != REG_NOERROR)
        return ret;
    }
  return REG_NOERROR;
}

/* Helper functions for re_string_construct_*.  */
static void
re_string_construct_common (str, len, pstr)
     const unsigned char *str;
     int len;
     re_string_t *pstr;
{
  pstr->mbs = str;
  pstr->cur_idx = 0;
  pstr->len = len;
#ifdef RE_ENABLE_I18N
  pstr->wcs = NULL;
#endif
  pstr->mbs_case = NULL;
  pstr->mbs_alloc = 0;
  pstr->mbs_case_alloc = 0;
}

#ifdef RE_ENABLE_I18N

/* Build wide character buffer for `pstr'.
   If the byte sequence of the string are:
     <mb1>(0), <mb1>(1), <mb2>(0), <mb2>(1), <sb3>
   Then wide character buffer will be:
     <wc1>   , WEOF    , <wc2>   , WEOF    , <wc3>
   We use WEOF for padding, they indicate that the position isn't
   a first byte of a multibyte character.  */

static reg_errcode_t
build_wcs_buffer (pstr)
     re_string_t *pstr;
{
  mbstate_t state, prev_st;
  wchar_t wc;
  int char_idx, char_len, mbclen;

  pstr->wcs = re_malloc (wchar_t, pstr->len + 1);
  if (pstr->wcs == NULL)
    return REG_ESPACE;

  memset (&state, '\0', sizeof (mbstate_t));
  char_len = pstr->len;
  for (char_idx = 0; char_idx < char_len ;)
    {
      int next_idx, remain_len = char_len - char_idx;
      prev_st = state;
      mbclen = mbrtowc (&wc, pstr->mbs + char_idx, remain_len, &state);
      if (mbclen == (size_t) -2 || mbclen == (size_t) -1 || mbclen == 0)
        /* We treat these cases as a singlebyte character.  */
        {
          mbclen = 1;
          wc = (wchar_t) pstr->mbs[char_idx++];
          state = prev_st;
        }
      /* Write wide character and padding.  */
      pstr->wcs[char_idx++] = wc;
      for (next_idx = char_idx + mbclen - 1; char_idx < next_idx ;)
        pstr->wcs[char_idx++] = WEOF;
    }
  return REG_NOERROR;
}

static reg_errcode_t
build_wcs_upper_buffer (pstr)
     re_string_t *pstr;
{
  mbstate_t state, prev_st;
  wchar_t wc;
  unsigned char *mbs_upper;
  int char_idx, char_len, mbclen;

  pstr->wcs = re_malloc (wchar_t, pstr->len + 1);
  mbs_upper = re_malloc (unsigned char, pstr->len + 1);
  if (pstr->wcs == NULL || mbs_upper == NULL)
    {
      pstr->wcs = NULL;
      return REG_ESPACE;
    }

  memset (&state, '\0', sizeof (mbstate_t));
  char_len = pstr->len;
  for (char_idx = 0 ; char_idx < char_len ; char_idx += mbclen)
    {
      int byte_idx, remain_len = char_len - char_idx;
      prev_st = state;
      mbclen = mbrtowc (&wc, pstr->mbs + char_idx, remain_len, &state);
      if (mbclen == 1)
        {
          pstr->wcs[char_idx] = wc;
          if (islower (pstr->mbs[char_idx]))
            mbs_upper[char_idx] = toupper (pstr->mbs[char_idx]);
          else
            mbs_upper[char_idx] = pstr->mbs[char_idx];
        }
      else if (mbclen == (size_t) -2 || mbclen == (size_t) -1 || mbclen == 0)
        /* We treat these cases as a singlebyte character.  */
        {
          mbclen = 1;
          pstr->wcs[char_idx] = (wchar_t) pstr->mbs[char_idx];
          mbs_upper[char_idx] = pstr->mbs[char_idx];
          state = prev_st;
        }
      else /* mbclen > 1 */
        {
          pstr->wcs[char_idx] = wc;
          if (iswlower (wc))
            wcrtomb (mbs_upper + char_idx, towupper (wc), &prev_st);
          else
            memcpy (mbs_upper + char_idx, pstr->mbs + char_idx, mbclen);
          for (byte_idx = 1 ; byte_idx < mbclen ; byte_idx++)
            pstr->wcs[char_idx + byte_idx] = WEOF;
        }
    }
  pstr->mbs = mbs_upper;
  pstr->mbs_alloc = 1;
  return REG_NOERROR;
}
#endif /* RE_ENABLE_I18N  */

static reg_errcode_t
build_upper_buffer (pstr)
     re_string_t *pstr;
{
  unsigned char *mbs_upper;
  int char_idx, char_len;

  mbs_upper = re_malloc (unsigned char, pstr->len + 1);
  if (mbs_upper == NULL)
    return REG_ESPACE;

  char_len = pstr->len;
  for (char_idx = 0 ; char_idx < char_len ; char_idx ++)
    {
      if (islower (pstr->mbs[char_idx]))
        mbs_upper[char_idx] = toupper (pstr->mbs[char_idx]);
      else
        mbs_upper[char_idx] = pstr->mbs[char_idx];
    }
  pstr->mbs = mbs_upper;
  pstr->mbs_alloc = 1;
  return REG_NOERROR;
}

/* Apply TRANS to the buffer in PSTR.  We assume that wide char buffer
   is already constructed if MB_CUR_MAX > 1.  */

static reg_errcode_t
re_string_translate_buffer (pstr, trans)
     re_string_t *pstr;
     RE_TRANSLATE_TYPE trans;
{
  int buf_idx;
  unsigned char *transed_buf, *transed_case_buf;
#ifdef DEBUG
  assert (trans != NULL);
#endif
  if (pstr->mbs_alloc)
    {
      transed_buf = (unsigned char *) pstr->mbs;
      transed_case_buf = re_malloc (unsigned char, pstr->len + 1);
      if (transed_case_buf == NULL)
        return REG_ESPACE;
      pstr->mbs_case_alloc = 1;
    }
  else
    {
      transed_buf = re_malloc (unsigned char, pstr->len + 1);
      if (transed_buf == NULL)
        return REG_ESPACE;
      transed_case_buf = NULL;
      pstr->mbs_alloc = 1;
    }
  for (buf_idx = 0 ; buf_idx < pstr->len ; buf_idx++)
    {
#ifdef RE_ENABLE_I18N
      if (MB_CUR_MAX > 1 && !re_string_is_single_byte_char (pstr, buf_idx))
        transed_buf[buf_idx] = pstr->mbs[buf_idx];
      else
#endif
        transed_buf[buf_idx] = trans[pstr->mbs[buf_idx]];
      if (transed_case_buf)
        {
#ifdef RE_ENABLE_I18N
         if (MB_CUR_MAX > 1 && !re_string_is_single_byte_char (pstr, buf_idx))
            transed_case_buf[buf_idx] = pstr->mbs_case[buf_idx];
          else
#endif
            transed_case_buf[buf_idx] = trans[pstr->mbs_case[buf_idx]];
        }
    }
  if (pstr->mbs_case_alloc == 1)
    {
      pstr->mbs = transed_buf;
      pstr->mbs_case = transed_case_buf;
    }
  else
    {
      pstr->mbs = transed_buf;
      pstr->mbs_case = transed_buf;
    }
  return REG_NOERROR;
}

static void
re_string_destruct (pstr)
     re_string_t *pstr;
{
#ifdef RE_ENABLE_I18N
  re_free (pstr->wcs);
#endif /* RE_ENABLE_I18N  */
  if (pstr->mbs_alloc)
    re_free ((void *) pstr->mbs);
  if (pstr->mbs_case_alloc)
    re_free ((void *) pstr->mbs_case);
}

/* Return the context at IDX in INPUT.  */
static unsigned int
re_string_context_at (input, idx, eflags, newline_anchor)
     const re_string_t *input;
     int idx, eflags, newline_anchor;
{
  int c;
  if (idx < 0 || idx == input->len)
    {
      unsigned int context = 0;
      if (idx < 0)
        context = CONTEXT_BEGBUF;
      else if (idx == input->len)
        context = CONTEXT_ENDBUF;

      if ((idx < 0 && !(eflags & REG_NOTBOL))
          || (idx == input->len && !(eflags & REG_NOTEOL)))
        return CONTEXT_NEWLINE | context;
      else
        return context;
    }
  c = re_string_byte_at (input, idx);
  if (IS_WORD_CHAR (c))
    return CONTEXT_WORD;
  return (newline_anchor && IS_NEWLINE (c)) ? CONTEXT_NEWLINE : 0;
}

/* Functions for set operation.  */

static reg_errcode_t
re_node_set_alloc (set, size)
     re_node_set *set;
     int size;
{
  set->alloc = size;
  set->nelem = 0;
  set->elems = re_malloc (int, size);
  if (set->elems == NULL)
    return REG_ESPACE;
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_init_1 (set, elem)
     re_node_set *set;
     int elem;
{
  set->alloc = 1;
  set->nelem = 1;
  set->elems = re_malloc (int, 1);
  if (set->elems == NULL)
    return REG_ESPACE;
  set->elems[0] = elem;
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_init_2 (set, elem1, elem2)
     re_node_set *set;
     int elem1, elem2;
{
  set->alloc = 2;
  set->elems = re_malloc (int, 2);
  if (set->elems == NULL)
    return REG_ESPACE;
  if (elem1 == elem2)
    {
      set->nelem = 1;
      set->elems[0] = elem1;
    }
  else
    {
      set->nelem = 2;
      if (elem1 < elem2)
        {
          set->elems[0] = elem1;
          set->elems[1] = elem2;
        }
      else
        {
          set->elems[0] = elem2;
          set->elems[1] = elem1;
        }
    }
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_init_copy (dest, src)
     re_node_set *dest;
     const re_node_set *src;
{
  dest->nelem = src->nelem;
  if (src->nelem > 0)
    {
      dest->alloc = dest->nelem;
      dest->elems = re_malloc (int, dest->alloc);
      if (dest->elems == NULL)
        return REG_ESPACE;
      memcpy (dest->elems, src->elems, src->nelem * sizeof (int));
    }
  else
    re_node_set_init_empty (dest);
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_intersect (dest, src1, src2)
     re_node_set *dest;
     const re_node_set *src1, *src2;
{
  int i1, i2, id;
  if (src1->nelem > 0 && src2->nelem > 0)
    {
      if (src1->nelem + src2->nelem > dest->alloc)
        {
          int *new_array;
          if (dest->alloc == 0)
            new_array = re_malloc (int, src1->nelem + src2->nelem);
          else
            new_array = re_realloc (dest->elems, int,
                                    src1->nelem + src2->nelem);
          dest->alloc = src1->nelem + src2->nelem;
          if (new_array == NULL)
            return REG_ESPACE;
          dest->elems = new_array;
        }
    }
  else
    {
      dest->nelem = 0;
      return REG_NOERROR;
    }

  for (i1 = i2 = id = 0 ; i1 < src1->nelem && i2 < src2->nelem ;)
    {
      if (src1->elems[i1] > src2->elems[i2])
        {
          ++i2;
          continue;
        }
      if (src1->elems[i1] == src2->elems[i2])
        dest->elems[id++] = src2->elems[i2++];
      ++i1;
    }
  dest->nelem = id;
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_add_intersect (dest, src1, src2)
     re_node_set *dest;
     const re_node_set *src1, *src2;
{
  int i1, i2, id;
  if (src1->nelem > 0 && src2->nelem > 0)
    {
      if (src1->nelem + src2->nelem + dest->nelem > dest->alloc)
        {
          int *new_array;
          if (dest->alloc == 0)
            new_array = re_malloc (int, src1->nelem + src2->nelem);
          else
            new_array = re_realloc (dest->elems, int,
                                    src1->nelem + src2->nelem + dest->nelem);
          dest->alloc = src1->nelem + src2->nelem + dest->nelem;
          if (new_array == NULL)
            return REG_ESPACE;
          dest->elems = new_array;
        }
    }
  else
    return REG_NOERROR;

  for (i1 = i2 = id = 0 ; i1 < src1->nelem && i2 < src2->nelem ;)
    {
      if (src1->elems[i1] > src2->elems[i2])
        {
          ++i2;
          continue;
        }
      if (src1->elems[i1] == src2->elems[i2])
        {
          while (id < dest->nelem && dest->elems[id] < src2->elems[i2])
            ++id;
          if (id < dest->nelem && dest->elems[id] == src2->elems[i2])
            ++id;
          else
            {
              memmove (dest->elems + id + 1, dest->elems + id,
                       sizeof (int) * (dest->nelem - id));
              dest->elems[id++] = src2->elems[i2++];
              ++dest->nelem;
            }
        }
      ++i1;
    }
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_init_union (dest, src1, src2)
     re_node_set *dest;
     const re_node_set *src1, *src2;
{
  int i1, i2, id;
  if (src1 != NULL && src1->nelem > 0 && src2 != NULL && src2->nelem > 0)
    {
      dest->alloc = src1->nelem + src2->nelem;
      dest->elems = re_malloc (int, dest->alloc);
      if (dest->elems == NULL)
        return REG_ESPACE;
    }
  else
    {
      if (src1 != NULL && src1->nelem > 0)
        return re_node_set_init_copy (dest, src1);
      else if (src2 != NULL && src2->nelem > 0)
        return re_node_set_init_copy (dest, src2);
      else
        re_node_set_init_empty (dest);
      return REG_NOERROR;
    }
  for (i1 = i2 = id = 0 ; i1 < src1->nelem && i2 < src2->nelem ;)
    {
      if (src1->elems[i1] > src2->elems[i2])
        {
          dest->elems[id++] = src2->elems[i2++];
          continue;
        }
      if (src1->elems[i1] == src2->elems[i2])
        ++i2;
      dest->elems[id++] = src1->elems[i1++];
    }
  if (i1 < src1->nelem)
    {
      memcpy (dest->elems + id, src1->elems + i1,
             (src1->nelem - i1) * sizeof (int));
      id += src1->nelem - i1;
    }
  else if (i2 < src2->nelem)
    {
      memcpy (dest->elems + id, src2->elems + i2,
             (src2->nelem - i2) * sizeof (int));
      id += src2->nelem - i2;
    }
  dest->nelem = id;
  return REG_NOERROR;
}

static reg_errcode_t
re_node_set_merge (dest, src)
     re_node_set *dest;
     const re_node_set *src;
{
  int si, di;
  if (src == NULL || src->nelem == 0)
    return REG_NOERROR;
  else if (dest == NULL)
    {
      dest = re_malloc (re_node_set, 1);
      return re_node_set_init_copy (dest, src);
    }
  if (dest->alloc < src->nelem + dest->nelem)
    {
      dest->alloc = 2 * (src->nelem + dest->alloc);
      dest->elems = re_realloc (dest->elems, int, dest->alloc);
    }

  for (si = 0, di = 0 ; si < src->nelem && di < dest->nelem ;)
    {
      int cp_from, ncp, mid, right, src_elem = src->elems[si];
      /* Binary search the spot we will add the new element.  */
      right = dest->nelem;
      while (di < right)
        {
          mid = (di + right) / 2;
          if (dest->elems[mid] < src_elem)
            di = mid + 1;
          else
            right = mid;
        }
      if (di >= dest->nelem)
        break;

      if (dest->elems[di] == src_elem)
        {
          /* Skip since, DEST already has the element.  */
          ++di;
          ++si;
          continue;
        }

      /* Skip the src elements which are less than dest->elems[di].  */
      cp_from = si;
      while (si < src->nelem && src->elems[si] < dest->elems[di])
        ++si;
      /* Copy these src elements.  */
      ncp = si - cp_from;
      memmove (dest->elems + di + ncp, dest->elems + di,
               sizeof (int) * (dest->nelem - di));
      memcpy (dest->elems + di, src->elems + cp_from,
              sizeof (int) * ncp);
      /* Update counters.  */
      di += ncp;
      dest->nelem += ncp;
    }

  /* Copy remaining src elements.  */
  if (si < src->nelem)
    {
      memcpy (dest->elems + di, src->elems + si,
              sizeof (int) * (src->nelem - si));
      dest->nelem += src->nelem - si;
    }
  return REG_NOERROR;
}

/* Insert the new element ELEM to the re_node_set* SET.
   return 0 if SET already has ELEM,
   return -1 if an error is occured, return 1 otherwise.  */

static int
re_node_set_insert (set, elem)
     re_node_set *set;
     int elem;
{
  int idx, right, mid;
  /* In case of the set is empty.  */
  if (set->elems == NULL || set->alloc == 0)
    {
      if (re_node_set_init_1 (set, elem) == REG_NOERROR)
        return 1;
      else
        return -1;
    }

  /* Binary search the spot we will add the new element.  */
  idx = 0;
  right = set->nelem;
  while (idx < right)
    {
      mid = (idx + right) / 2;
      if (set->elems[mid] < elem)
        idx = mid + 1;
      else
        right = mid;
    }

  /* Realloc if we need.  */
  if (set->alloc < set->nelem + 1)
    {
      int *new_array;
      set->alloc = set->alloc * 2;
      new_array = re_malloc (int, set->alloc);
      if (new_array == NULL)
        return -1;
      /* Copy the elements they are followed by the new element.  */
      if (idx > 0)
        memcpy (new_array, set->elems, sizeof (int) * (idx));
      /* Copy the elements which follows the new element.  */
      if (set->nelem - idx > 0)
        memcpy (new_array + idx + 1, set->elems + idx,
		sizeof (int) * (set->nelem - idx));
      set->elems = new_array;
    }
  else
    {
      /* Move the elements which follows the new element.  */
      if (set->nelem - idx > 0)
        memmove (set->elems + idx + 1, set->elems + idx,
                 sizeof (int) * (set->nelem - idx));
    }
  /* Insert the new element.  */
  set->elems[idx] = elem;
  ++set->nelem;
  return 1;
}

/* Compare two node sets SET1 and SET2.
   return 1 if SET1 and SET2 are equivalent, retrun 0 otherwise.  */

static int
re_node_set_compare (set1, set2)
     const re_node_set *set1, *set2;
{
  int i;
  if (set1 == NULL || set2 == NULL || set1->nelem != set2->nelem)
    return 0;
  for (i = 0 ; i < set1->nelem ; i++)
    if (set1->elems[i] != set2->elems[i])
      return 0;
  return 1;
}

/* Return 1 if SET contains the element ELEM, return 0 otherwise.  */

static int
re_node_set_contains (set, elem)
     const re_node_set *set;
     int elem;
{
  int idx, right, mid;
  if (set->nelem <= 0)
    return 0;

  /* Binary search the element.  */
  idx = 0;
  right = set->nelem - 1;
  while (idx < right)
    {
      mid = (idx + right) / 2;
      if (set->elems[mid] < elem)
        idx = mid + 1;
      else
        right = mid;
    }
  return set->elems[idx] == elem;
}

static void
re_node_set_remove_at (set, idx)
     re_node_set *set;
     int idx;
{
  if (idx < 0 || idx >= set->nelem)
    return;
  if (idx < set->nelem - 1)
    memmove (set->elems + idx, set->elems + idx + 1,
             sizeof (int) * (set->nelem - idx - 1));
  --set->nelem;
}


/* Add the token TOKEN to dfa->nodes, and return the index of the token.
   Or return -1, if an error will be occured.  */

static int
re_dfa_add_node (dfa, token, mode)
     re_dfa_t *dfa;
     re_token_t token;
     int mode;
{
  if (dfa->nodes_len >= dfa->nodes_alloc)
    {
      re_token_t *new_array;
      dfa->nodes_alloc *= 2;
      new_array = re_realloc (dfa->nodes, re_token_t, dfa->nodes_alloc);
      if (new_array == NULL)
        return -1;
      else
        dfa->nodes = new_array;
      if (mode)
        {
          int *new_firsts, *new_nexts;
          re_node_set *new_edests, *new_eclosures, *new_inveclosures;

          new_firsts = re_realloc (dfa->firsts, int, dfa->nodes_alloc);
          new_nexts = re_realloc (dfa->nexts, int, dfa->nodes_alloc);
          new_edests = re_realloc (dfa->edests, re_node_set, dfa->nodes_alloc);
          new_eclosures = re_realloc (dfa->eclosures, re_node_set,
                                      dfa->nodes_alloc);
          new_inveclosures = re_realloc (dfa->inveclosures, re_node_set,
                                         dfa->nodes_alloc);
          if (new_firsts == NULL || new_nexts == NULL || new_edests == NULL
              || new_eclosures == NULL || new_inveclosures == NULL)
            return -1;
          dfa->firsts = new_firsts;
          dfa->nexts = new_nexts;
          dfa->edests = new_edests;
          dfa->eclosures = new_eclosures;
          dfa->inveclosures = new_inveclosures;
        }
    }
  dfa->nodes[dfa->nodes_len] = token;
  dfa->nodes[dfa->nodes_len].duplicated = 0;
  return dfa->nodes_len++;
}

static unsigned int inline
calc_state_hash (nodes, context)
     const re_node_set *nodes;
     unsigned int context;
{
  unsigned int hash = nodes->nelem + context;
  int i;
  for (i = 0 ; i < nodes->nelem ; i++)
    hash += nodes->elems[i];
  return hash;
}

/* Search for the state whose node_set is equivalent to NODES.
   Return the pointer to the state, if we found it in the DFA.
   Otherwise create the new one and return it.  */

static re_dfastate_t *
re_acquire_state (dfa, nodes)
     re_dfa_t *dfa;
     const re_node_set *nodes;
{
  unsigned int hash;
  struct re_state_table_entry *spot;
  int i;
  if (nodes->nelem == 0)
    return NULL;
  hash = calc_state_hash (nodes, 0);
  spot = dfa->state_table + (hash & dfa->state_hash_mask);

  if (spot->alloc == 0)
    {
      /* Currently there are only one state in this spot.  */
      if (spot->entry.state != NULL && hash == spot->entry.state->hash
          && re_node_set_compare (&spot->entry.state->nodes, nodes))
        return spot->entry.state;
    }
  else
    for (i = 0 ; i < spot->num ; i++)
      {
        re_dfastate_t *state = spot->entry.array[i];
        if (hash != state->hash)
          continue;
        if (re_node_set_compare (&state->nodes, nodes))
          return state;
      }

  /* There are no appropriate state in the dfa, create the new one.  */
  return create_ci_newstate (dfa, nodes, hash);
}

/* Search for the state whose node_set is equivalent to NODES and
   whose context is equivalent to CONTEXT.
   Return the pointer to the state, if we found it in the DFA.
   Otherwise create the new one and return it.  */

static re_dfastate_t *
re_acquire_state_context (dfa, nodes, context)
     re_dfa_t *dfa;
     const re_node_set *nodes;
     unsigned int context;
{
  unsigned int hash;
  struct re_state_table_entry *spot;
  int i;
  if (nodes->nelem == 0)
    return NULL;
  hash = calc_state_hash (nodes, context);
  spot = dfa->state_table + (hash & dfa->state_hash_mask);

  if (spot->alloc == 0)
    {
      /* Currently there are only one state in this spot.  */
      if (spot->entry.state != NULL && hash == spot->entry.state->hash
          && re_node_set_compare (&spot->entry.state->nodes, nodes)
          && spot->entry.state->context == context)
        return spot->entry.state;
    }
  else
    for (i = 0 ; i < spot->num ; i++)
      {
        re_dfastate_t *state = spot->entry.array[i];
        if (hash != state->hash)
          continue;
        if (re_node_set_compare (state->entrance_nodes, nodes)
            && state->context == context)
          return state;
      }
  /* There are no appropriate state in `dfa', create the new one.  */
  return create_cd_newstate (dfa, nodes, context, hash);
}

static re_dfastate_t *
create_newstate_common (dfa, nodes, hash)
     re_dfa_t *dfa;
     const re_node_set *nodes;
     unsigned int hash;
{
  re_dfastate_t *newstate;
  newstate = (re_dfastate_t *) calloc (sizeof (re_dfastate_t), 1);
  re_node_set_init_copy (&newstate->nodes, nodes);
  newstate->trtable = NULL;
  newstate->trtable_search = NULL;
  newstate->hash = hash;
  return newstate;
}

static void
register_state (dfa, newstate, hash)
     re_dfa_t *dfa;
     re_dfastate_t *newstate;
     unsigned int hash;
{
  struct re_state_table_entry *spot;
  spot = dfa->state_table + (hash & dfa->state_hash_mask);

  if (spot->alloc <= spot->num)
    {
      re_dfastate_t **new_array;

      /* XXX Is spot->entry.array == NULL if spot->alloc == 0?  If yes
	 the if can go away and only realloc is needed.  */
      if (spot->alloc == 0)
        {
          spot->alloc = 4;
          new_array = re_malloc (re_dfastate_t *, spot->alloc);
	  if (new_array == NULL)
	    /* XXX return value */
	    return;
          new_array[0] = spot->entry.state;
        }
      else
        {
          spot->alloc = 2 * spot->num;
          new_array = re_realloc (spot->entry.array, re_dfastate_t *,
                                  spot->alloc);
        }
      spot->entry.array = new_array;
    }
  spot->entry.array[spot->num++] = newstate;
}

static re_dfastate_t *
create_ci_newstate (dfa, nodes, hash)
     re_dfa_t *dfa;
     const re_node_set *nodes;
     unsigned int hash;
{
  int i;
  re_dfastate_t *newstate;
  newstate = create_newstate_common (dfa, nodes, hash);
  newstate->entrance_nodes = &newstate->nodes;

  for (i = 0 ; i < nodes->nelem ; i++)
    {
      re_token_t *node = dfa->nodes + nodes->elems[i];
      re_token_type_t type = node->type;
      if (type == CHARACTER)
        continue;

      /* If the state has the halt node, the state is a halt state.  */
      else if (type == END_OF_RE)
        newstate->halt = 1;
      else if (type == COMPLEX_BRACKET
               || (type == OP_PERIOD && MB_CUR_MAX > 1))
        newstate->accept_mb = 1;
      else if (type == OP_BACK_REF)
        newstate->has_backref = 1;
      else if (type == ANCHOR || OP_CONTEXT_NODE)
        {
          newstate->has_constraint = 1;
          if (type == OP_CONTEXT_NODE
              && dfa->nodes[node->opr.ctx_info->entity].type == END_OF_RE)
            newstate->halt = 1;
        }
    }

  register_state (dfa, newstate, hash);
  return newstate;
}

static re_dfastate_t *
create_cd_newstate (dfa, nodes, context, hash)
     re_dfa_t *dfa;
     const re_node_set *nodes;
     unsigned int context, hash;
{
  int i, nctx_nodes = 0;
  re_dfastate_t *newstate;

  newstate = create_newstate_common (dfa, nodes, hash);
  newstate->context = context;
  newstate->entrance_nodes = &newstate->nodes;

  for (i = 0 ; i < nodes->nelem ; i++)
    {
      unsigned int constraint = 0;
      re_token_t *node = dfa->nodes + nodes->elems[i];
      re_token_type_t type = node->type;
      if (type == CHARACTER)
        continue;

      /* If the state has the halt node, the state is a halt state.  */
      else if (type == END_OF_RE)
        newstate->halt = 1;
      else if (type == COMPLEX_BRACKET
               || (type == OP_PERIOD && MB_CUR_MAX > 1))
        newstate->accept_mb = 1;
      else if (type == OP_BACK_REF)
        newstate->has_backref = 1;
      else if (type == ANCHOR)
        constraint = node->opr.ctx_type;
      else if (type == OP_CONTEXT_NODE)
        {
          re_token_type_t ctype = dfa->nodes[node->opr.ctx_info->entity].type;
          constraint = node->constraint;
          if (ctype == END_OF_RE)
            newstate->halt = 1;
          else if (ctype == OP_BACK_REF)
            newstate->has_backref = 1;
          else if (ctype == COMPLEX_BRACKET
                   || (type == OP_PERIOD && MB_CUR_MAX > 1))
            newstate->accept_mb = 1;
        }

      if (constraint)
        {
          if (newstate->entrance_nodes == &newstate->nodes)
            {
              newstate->entrance_nodes = re_malloc (re_node_set, 1);
	      if (newstate->entrance_nodes == NULL)
		/* XXX Return which value?  */
		return NULL;
              re_node_set_init_copy (newstate->entrance_nodes, nodes);
              nctx_nodes = 0;
              newstate->has_constraint = 1;
            }

          if (NOT_SATISFY_PREV_CONSTRAINT (constraint,context))
            {
              re_node_set_remove_at (&newstate->nodes, i - nctx_nodes);
              ++nctx_nodes;
            }
        }
    }
  register_state (dfa, newstate, hash);
  return newstate;
}
