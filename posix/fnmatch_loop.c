/* Copyright (C) 1991-1993, 1996-1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* Match STRING against the filename pattern PATTERN, returning zero if
   it matches, nonzero if not.  */
static int FCT (const CHAR *pattern, const CHAR *string,
		int no_leading_period, int flags) internal_function;

static int
internal_function
FCT (pattern, string, no_leading_period, flags)
     const CHAR *pattern;
     const CHAR *string;
     int no_leading_period;
     int flags;
{
  register const CHAR *p = pattern, *n = string;
  register UCHAR c;
#ifdef _LIBC
  const UCHAR *collseq = (const UCHAR *)
    _NL_CURRENT(LC_COLLATE, CONCAT(_NL_COLLATE_COLLSEQ,SUFFIX));
# ifdef WIDE_CHAR_VERSION
  const wint_t *names = (const wint_t *)
    _NL_CURRENT (LC_COLLATE, _NL_COLLATE_NAMES);
  size_t size = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_HASH_SIZE);
  size_t layers = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_HASH_LAYERS);
# endif
#endif

  while ((c = *p++) != L('\0'))
    {
      c = FOLD (c);

      switch (c)
	{
	case L('?'):
	  if (*n == L('\0'))
	    return FNM_NOMATCH;
	  else if (*n == L('/') && (flags & FNM_FILE_NAME))
	    return FNM_NOMATCH;
	  else if (*n == L('.') && no_leading_period
		   && (n == string
		       || (n[-1] == L('/') && (flags & FNM_FILE_NAME))))
	    return FNM_NOMATCH;
	  break;

	case L('\\'):
	  if (!(flags & FNM_NOESCAPE))
	    {
	      c = *p++;
	      if (c == L('\0'))
		/* Trailing \ loses.  */
		return FNM_NOMATCH;
	      c = FOLD (c);
	    }
	  if (FOLD ((UCHAR) *n) != c)
	    return FNM_NOMATCH;
	  break;

	case L('*'):
	  if (*n == L('.') && no_leading_period
	      && (n == string
		  || (n[-1] == L('/') && (flags & FNM_FILE_NAME))))
	    return FNM_NOMATCH;

	  for (c = *p++; c == L('?') || c == L('*'); c = *p++)
	    {
	      if (*n == L('/') && (flags & FNM_FILE_NAME))
		/* A slash does not match a wildcard under FNM_FILE_NAME.  */
		return FNM_NOMATCH;
	      else if (c == L('?'))
		{
		  /* A ? needs to match one character.  */
		  if (*n == L('\0'))
		    /* There isn't another character; no match.  */
		    return FNM_NOMATCH;
		  else
		    /* One character of the string is consumed in matching
		       this ? wildcard, so *??? won't match if there are
		       less than three characters.  */
		    ++n;
		}
	    }

	  if (c == L('\0'))
	    /* The wildcard(s) is/are the last element of the pattern.
	       If the name is a file name and contains another slash
	       this does mean it cannot match.  If the FNM_LEADING_DIR
	       flag is set and exactly one slash is following, we have
	       a match.  */
	    {
	      int result = (flags & FNM_FILE_NAME) == 0 ? 0 : FNM_NOMATCH;

	      if (flags & FNM_FILE_NAME)
		{
		  const CHAR *slashp = STRCHR (n, L('/'));

		  if (flags & FNM_LEADING_DIR)
		    {
		      if (slashp != NULL
			  && STRCHR (slashp + 1, L('/')) == NULL)
			result = 0;
		    }
		  else
		    {
		      if (slashp == NULL)
			result = 0;
		    }
		}

	      return result;
	    }
	  else
	    {
	      const CHAR *endp;

	      endp = STRCHRNUL (n, (flags & FNM_FILE_NAME) ? L('/') : L('\0'));

	      if (c == L('['))
		{
		  int flags2 = ((flags & FNM_FILE_NAME)
				? flags : (flags & ~FNM_PERIOD));

		  for (--p; n < endp; ++n)
		    if (FCT (p, n, (no_leading_period
				    && (n == string
					|| (n[-1] == L('/')
					    && (flags & FNM_FILE_NAME)))),
			     flags2) == 0)
		      return 0;
		}
	      else if (c == L('/') && (flags & FNM_FILE_NAME))
		{
		  while (*n != L('\0') && *n != L('/'))
		    ++n;
		  if (*n == L('/')
		      && (FCT (p, n + 1, flags & FNM_PERIOD, flags) == 0))
		    return 0;
		}
	      else
		{
		  int flags2 = ((flags & FNM_FILE_NAME)
				? flags : (flags & ~FNM_PERIOD));

		  if (c == L('\\') && !(flags & FNM_NOESCAPE))
		    c = *p;
		  c = FOLD (c);
		  for (--p; n < endp; ++n)
		    if (FOLD ((UCHAR) *n) == c
			&& (FCT (p, n, (no_leading_period
					&& (n == string
					    || (n[-1] == L('/')
						&& (flags & FNM_FILE_NAME)))),
				 flags2) == 0))
		      return 0;
		}
	    }

	  /* If we come here no match is possible with the wildcard.  */
	  return FNM_NOMATCH;

	case L('['):
	  {
	    static int posixly_correct;
	    /* Nonzero if the sense of the character class is inverted.  */
	    register int not;
	    CHAR cold;

	    if (posixly_correct == 0)
	      posixly_correct = getenv ("POSIXLY_CORRECT") != NULL ? 1 : -1;

	    if (*n == L('\0'))
	      return FNM_NOMATCH;

	    if (*n == L('.') && no_leading_period
		&& (n == string
		    || (n[-1] == L('/') && (flags & FNM_FILE_NAME))))
	      return FNM_NOMATCH;

	    if (*n == L('/') && (flags & FNM_FILE_NAME))
	      /* `/' cannot be matched.  */
	      return FNM_NOMATCH;

	    not = (*p == L('!') || (posixly_correct < 0 && *p == L('^')));
	    if (not)
	      ++p;

	    c = *p++;
	    for (;;)
	      {
		UCHAR fn = FOLD ((UCHAR) *n);

		if (!(flags & FNM_NOESCAPE) && c == L('\\'))
		  {
		    if (*p == L('\0'))
		      return FNM_NOMATCH;
		    c = FOLD ((UCHAR) *p);
		    ++p;

		    if (c == fn)
		      goto matched;
		  }
		else if (c == L('[') && *p == L(':'))
		  {
		    /* Leave room for the null.  */
		    CHAR str[CHAR_CLASS_MAX_LENGTH + 1];
		    size_t c1 = 0;
#if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
		    wctype_t wt;
#endif
		    const CHAR *startp = p;

		    for (;;)
		      {
			if (c1 == CHAR_CLASS_MAX_LENGTH)
			  /* The name is too long and therefore the pattern
			     is ill-formed.  */
			  return FNM_NOMATCH;

			c = *++p;
			if (c == L(':') && p[1] == L(']'))
			  {
			    p += 2;
			    break;
			  }
			if (c < L('a') || c >= L('z'))
			  {
			    /* This cannot possibly be a character class name.
			       Match it as a normal range.  */
			    p = startp;
			    c = L('[');
			    goto normal_bracket;
			  }
			str[c1++] = c;
		      }
		    str[c1] = L('\0');

#if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
		    wt = IS_CHAR_CLASS (str);
		    if (wt == 0)
		      /* Invalid character class name.  */
		      return FNM_NOMATCH;

		    /* The following code is glibc specific but does
		       there a good job in sppeding up the code since
		       we can avoid the btowc() call.  The
		       IS_CHAR_CLASS call will return a bit mask for
		       the 32-bit table.  We have to convert it to a
		       bitmask for the __ctype_b table.  This has to
		       be done based on the byteorder as can be seen
		       below.  In any case we will fall back on the
		       code using btowc() if the class is not one of
		       the standard classes.  */
# if defined _LIBC && ! WIDE_CHAR_VERSION
#  if __BYTE_ORDER == __LITTLE_ENDIAN
		    if ((wt & 0xf0ffff) == 0)
		      {
			wt >>= 16;
			if ((__ctype_b[(UCHAR) *n] & wt) != 0)
			  goto matched;
		      }
#  else
		    if (wt <= 0x800)
		      {
			if ((__ctype_b[(UCHAR) *n] & wt) != 0)
			  goto matched;
		      }
#  endif
		    else
# endif
		      if (ISWCTYPE (BTOWC ((UCHAR) *n), wt))
			goto matched;
#else
		    if ((STREQ (str, L("alnum")) && ISALNUM ((UCHAR) *n))
			|| (STREQ (str, L("alpha")) && ISALPHA ((UCHAR) *n))
			|| (STREQ (str, L("blank")) && ISBLANK ((UCHAR) *n))
			|| (STREQ (str, L("cntrl")) && ISCNTRL ((UCHAR) *n))
			|| (STREQ (str, L("digit")) && ISDIGIT ((UCHAR) *n))
			|| (STREQ (str, L("graph")) && ISGRAPH ((UCHAR) *n))
			|| (STREQ (str, L("lower")) && ISLOWER ((UCHAR) *n))
			|| (STREQ (str, L("print")) && ISPRINT ((UCHAR) *n))
			|| (STREQ (str, L("punct")) && ISPUNCT ((UCHAR) *n))
			|| (STREQ (str, L("space")) && ISSPACE ((UCHAR) *n))
			|| (STREQ (str, L("upper")) && ISUPPER ((UCHAR) *n))
			|| (STREQ (str, L("xdigit")) && ISXDIGIT ((UCHAR) *n)))
		      goto matched;
#endif
		    c = *p++;
		  }
		else if (c == L('\0'))
		  /* [ (unterminated) loses.  */
		  return FNM_NOMATCH;
		else
		  {
		    c = FOLD (c);
		  normal_bracket:
		    if (c == fn)
		      goto matched;

		    cold = c;
		    c = *p++;

		    if (c == L('-') && *p != L(']'))
		      {
#if _LIBC
			/* We have to find the collation sequence
			   value for C.  Collation sequence is nothing
			   we can regularly access.  The sequence
			   value is defined by the order in which the
			   definitions of the collation values for the
			   various characters appear in the source
			   file.  A strange concept, nowhere
			   documented.  */
			int32_t fseqidx;
			int32_t lseqidx;
			UCHAR cend = *p++;
# ifdef WIDE_CHAR_VERSION
			size_t cnt;
# endif

			if (!(flags & FNM_NOESCAPE) && cend == L('\\'))
			  cend = *p++;
			if (cend == L('\0'))
			  return FNM_NOMATCH;

# ifdef WIDE_CHAR_VERSION
			/* Search in the `names' array for the characters.  */
			fseqidx = fn % size;
			cnt = 0;
			while (names[fseqidx] != fn)
			  {
			    if (++cnt == layers)
			      /* XXX We don't know anything about
				 the character we are supposed to
				 match.  This means we are failing.  */
			      goto range_not_matched;

			    fseqidx += size;
			  }
			lseqidx = cold % size;
			cnt = 0;
			while (names[lseqidx] != cold)
			  {
			    if (++cnt == layers)
			      {
				lseqidx = -1;
				break;
			      }
			    lseqidx += size;
			  }
# else
			fseqidx = fn;
			lseqidx = cold;
# endif

			/* XXX It is not entirely clear to me how to handle
			   characters which are not mentioned in the
			   collation specification.  */
			if (
# ifdef WIDE_CHAR_VERSION
			    lseqidx == -1 ||
# endif
			    collseq[lseqidx] <= collseq[fseqidx])
			  {
			    /* We have to look at the upper bound.  */
			    int32_t hseqidx;

			    cend = FOLD (cend);
# ifdef WIDE_CHAR_VERSION
			    hseqidx = cend % size;
			    cnt = 0;
			    while (names[hseqidx] != cend)
			      {
				if (++cnt == layers)
				  {
				    /* Hum, no information about the upper
				       bound.  The matching succeeds if the
				       lower bound is matched exactly.  */
				    if (lseqidx == -1 || cold != fn)
				      goto range_not_matched;

				    goto matched;
				  }
			      }
# else
			    hseqidx = cend;
# endif

			    if (
# ifdef WIDE_CHAR_VERSION
				(lseqidx == -1
				 && collseq[fseqidx] == collseq[hseqidx]) ||
# endif
				collseq[fseqidx] <= collseq[hseqidx])
			      goto matched;
			  }
# ifdef WIDE_CHAR_VERSION
		      range_not_matched:
# endif
#else
			/* We use a boring value comparison of the character
			   values.  This is better than comparing using
			   `strcoll' since the latter would have surprising
			   and sometimes fatal consequences.  */
			UCHAR cend = *p++;

			if (!(flags & FNM_NOESCAPE) && cend == L('\\'))
			  cend = *p++;
			if (cend == L('\0'))
			  return FNM_NOMATCH;

			/* It is a range.  */
			if (cold <= fc && fc <= c)
			  goto matched;
#endif

			c = *p++;
		      }
		  }

		if (c == L(']'))
		  break;
	      }

	    if (!not)
	      return FNM_NOMATCH;
	    break;

	  matched:
	    /* Skip the rest of the [...] that already matched.  */
	    do
	      {
		c = *p++;

		if (c == L('\0'))
		  /* [... (unterminated) loses.  */
		  return FNM_NOMATCH;

		if (!(flags & FNM_NOESCAPE) && c == L('\\'))
		  {
		    if (*p == L('\0'))
		      return FNM_NOMATCH;
		    /* XXX 1003.2d11 is unclear if this is right.  */
		    ++p;
		  }
		else if (c == L('[') && *p == L(':'))
		  {
		    do
		      if (*++p == L('\0'))
			return FNM_NOMATCH;
		    while (*p != L(':') || p[1] == L(']'));
		    p += 2;
		    c = *p;
		  }
	      }
	    while (c != L(']'));
	    if (not)
	      return FNM_NOMATCH;
	  }
	  break;

	default:
	  if (c != FOLD ((UCHAR) *n))
	    return FNM_NOMATCH;
	}

      ++n;
    }

  if (*n == '\0')
    return 0;

  if ((flags & FNM_LEADING_DIR) && *n == L('/'))
    /* The FNM_LEADING_DIR flag says that "foo*" matches "foobar/frobozz".  */
    return 0;

  return FNM_NOMATCH;
}

#undef FOLD
#undef CHAR
#undef UCHAR
#undef FCT
#undef STRCHR
#undef STRCHRNUL
#undef STRCOLL
#undef L
#undef BTOWC
#undef SUFFIX
