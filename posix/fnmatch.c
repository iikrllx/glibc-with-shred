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

#if HAVE_CONFIG_H
# include <config.h>
#endif

/* Enable GNU extensions in fnmatch.h.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1
#endif

#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <ctype.h>

#if HAVE_STRING_H || defined _LIBC
# include <string.h>
#else
# include <strings.h>
#endif

#if defined STDC_HEADERS || defined _LIBC
# include <stdlib.h>
#endif

/* For platform which support the ISO C amendement 1 functionality we
   support user defined character classes.  */
#if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
/* Solaris 2.5 has a bug: <wchar.h> must be included before <wctype.h>.  */
# include <wchar.h>
# include <wctype.h>
#endif

/* Comment out all this code if we are using the GNU C Library, and are not
   actually compiling the library itself.  This code is part of the GNU C
   Library, but also included in many other GNU distributions.  Compiling
   and linking in this code is a waste when using the GNU C library
   (especially if it is a shared library).  Rather than having every GNU
   program understand `configure --with-gnu-libc' and omit the object files,
   it is simpler to just do this in the source for each such file.  */

#if defined _LIBC || !defined __GNU_LIBRARY__


# if defined STDC_HEADERS || !defined isascii
#  define ISASCII(c) 1
# else
#  define ISASCII(c) isascii(c)
# endif

# ifdef isblank
#  define ISBLANK(c) (ISASCII (c) && isblank (c))
# else
#  define ISBLANK(c) ((c) == ' ' || (c) == '\t')
# endif
# ifdef isgraph
#  define ISGRAPH(c) (ISASCII (c) && isgraph (c))
# else
#  define ISGRAPH(c) (ISASCII (c) && isprint (c) && !isspace (c))
# endif

# define ISPRINT(c) (ISASCII (c) && isprint (c))
# define ISDIGIT(c) (ISASCII (c) && isdigit (c))
# define ISALNUM(c) (ISASCII (c) && isalnum (c))
# define ISALPHA(c) (ISASCII (c) && isalpha (c))
# define ISCNTRL(c) (ISASCII (c) && iscntrl (c))
# define ISLOWER(c) (ISASCII (c) && islower (c))
# define ISPUNCT(c) (ISASCII (c) && ispunct (c))
# define ISSPACE(c) (ISASCII (c) && isspace (c))
# define ISUPPER(c) (ISASCII (c) && isupper (c))
# define ISXDIGIT(c) (ISASCII (c) && isxdigit (c))

# define STREQ(s1, s2) ((strcmp (s1, s2) == 0))

# if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
/* The GNU C library provides support for user-defined character classes
   and the functions from ISO C amendement 1.  */
#  ifdef CHARCLASS_NAME_MAX
#   define CHAR_CLASS_MAX_LENGTH CHARCLASS_NAME_MAX
#  else
/* This shouldn't happen but some implementation might still have this
   problem.  Use a reasonable default value.  */
#   define CHAR_CLASS_MAX_LENGTH 256
#  endif

#  ifdef _LIBC
#   define IS_CHAR_CLASS(string) __wctype (string)
#  else
#   define IS_CHAR_CLASS(string) wctype (string)
#  endif

#  ifdef _LIBC
#   define ISWCTYPE(WC, WT)	__iswctype (WC, WT)
#  else
#   define ISWCTYPE(WC, WT)	iswctype (WC, WT)
#  endif

#  if (HAVE_MBSTATE_T && HAVE_MBSRTOWCS) || _LIBC
/* In this case we are implementing the multibyte character handling.  */
#   define HANDLE_MULTIBYTE	1
#  endif

# else
#  define CHAR_CLASS_MAX_LENGTH  6 /* Namely, `xdigit'.  */

#  define IS_CHAR_CLASS(string)						      \
   (STREQ (string, "alpha") || STREQ (string, "upper")			      \
    || STREQ (string, "lower") || STREQ (string, "digit")		      \
    || STREQ (string, "alnum") || STREQ (string, "xdigit")		      \
    || STREQ (string, "space") || STREQ (string, "print")		      \
    || STREQ (string, "punct") || STREQ (string, "graph")		      \
    || STREQ (string, "cntrl") || STREQ (string, "blank"))
# endif

/* Avoid depending on library functions or files
   whose names are inconsistent.  */

# if !defined _LIBC && !defined getenv
extern char *getenv ();
# endif

# ifndef errno
extern int errno;
# endif

/* This function doesn't exist on most systems.  */

# if !defined HAVE___STRCHRNUL && !defined _LIBC
static char *
__strchrnul (s, c)
     const char *s;
     int c;
{
  char *result = strchr (s, c);
  if (result == NULL)
    result = strchr (s, '\0');
  return result;
}
# endif

# if HANDLE_MULTIBYTE && !defined HAVE___STRCHRNUL && !defined _LIBC
static wchar_t *
__wcschrnul (s, c)
     const wchar_t *s;
     wint_t c;
{
  wchar_t *result = wcschr (s, c);
  if (result == NULL)
    result = wcschr (s, '\0');
  return result;
}
# endif

# ifndef internal_function
/* Inside GNU libc we mark some function in a special way.  In other
   environments simply ignore the marking.  */
#  define internal_function
# endif

/* Note that this evaluates C many times.  */
# ifdef _LIBC
#  define FOLD(c) ((flags & FNM_CASEFOLD) ? tolower (c) : (c))
# else
#  define FOLD(c) ((flags & FNM_CASEFOLD) && ISUPPER (c) ? tolower (c) : (c))
# endif
# define CHAR	char
# define UCHAR	unsigned char
# define FCT	internal_fnmatch
# define L(CS)	CS
# ifdef _LIBC
#  define BTOWC(C)	__btowc (C)
# else
#  define BTOWC(C)	btowc (C)
# endif
# define STRCHR(S, C)	strchr (S, C)
# define STRCHRNUL(S, C) __strchrnul (S, C)
# include "fnmatch_loop.c"


# if HANDLE_MULTIBYTE
/* Note that this evaluates C many times.  */
#  ifdef _LIBC
#   define FOLD(c) ((flags & FNM_CASEFOLD) ? towlower (c) : (c))
#  else
#   define FOLD(c) ((flags & FNM_CASEFOLD) && ISUPPER (c) ? towlower (c) : (c))
#  endif
#  define CHAR	wchar_t
#  define UCHAR	wint_t
#  define FCT	internal_fnwmatch
#  define L(CS)	L##CS
#  define BTOWC(C)	(C)
#  define STRCHR(S, C)	wcschr (S, C)
#  define STRCHRNUL(S, C) __wcschrnul (S, C)

#  undef IS_CHAR_CLASS
#  ifdef _LIBC
/* We have to convert the wide character string in a multibyte string.  But
   we know that the character class names are ASCII strings and since the
   internal wide character encoding is UCS4 we can use a simplified method
   to convert the string to a multibyte character string.  */
static wctype_t
is_char_class (const wchar_t *wcs)
{
  char s[CHAR_CLASS_MAX_LENGTH + 1];
  char *cp = s;

  do
    {
      if (*wcs < 0x20 || *wcs >= 0x7f)
	return 0;

      *cp++ = (char) *wcs;
    }
  while (*wcs++ != L'\0');

  return __wctype (s);
}
#  else
/* Since we cannot assume anything about the internal encoding we have to
   convert the string back to multibyte representation the hard way.  */
static wctype_t
is_char_class (const wchar_t *wcs)
{
  mbstate_t ps;
  const wchar_t *pwc;
  char *s;
  size_t n;

  memset (&ps, '\0', sizeof (ps));

  pwc = wcs;
  n = wcsrtombs (NULL, &pwc, 0, &ps);
  if (n == (size_t) -1)
    /* Something went wrong.  */
    return 0;

  s = alloca (n + 1);
  assert (mbsinit (&ps));
  pwc = wcs;
  (void) wcsrtombs (s, &pwc, n + 1, &ps);

  return wctype (s);
}
#  endif
#  define IS_CHAR_CLASS(string) is_char_class (string)

#  include "fnmatch_loop.c"
# endif

int
fnmatch (pattern, string, flags)
     const char *pattern;
     const char *string;
     int flags;
{
# if HANDLE_MULTIBYTE
  mbstate_t ps;
  size_t n;
  wchar_t *wpattern;
  wchar_t *wstring;

  if (MB_CUR_MAX == 1)
    /* This is an optimization for 8-bit character set.  */
    return internal_fnmatch (pattern, string, flags & FNM_PERIOD, flags);

  /* Convert the strings into wide characters.  */
  memset (&ps, '\0', sizeof (ps));
  n = mbsrtowcs (NULL, &pattern, 0, &ps);
  if (n == (size_t) -1)
    /* Something wrong.
       XXX Do we have to set `errno' to something which mbsrtows hasn't
       already done?  */
    return -1;
  wpattern = (wchar_t *) alloca ((n + 1) * sizeof (wchar_t));
  assert (mbsinit (&ps));
  (void) mbsrtowcs (wpattern, &pattern, n + 1, &ps);

  assert (mbsinit (&ps));
  n = mbsrtowcs (NULL, &string, 0, &ps);
  if (n == (size_t) -1)
    /* Something wrong.
       XXX Do we have to set `errno' to something which mbsrtows hasn't
       already done?  */
    return -1;
  wstring = (wchar_t *) alloca ((n + 1) * sizeof (wchar_t));
  assert (mbsinit (&ps));
  (void) mbsrtowcs (wstring, &string, n + 1, &ps);

  return internal_fnwmatch (wpattern, wstring, flags & FNM_PERIOD, flags);
# else
  return internal_fnmatch (pattern, string, flags & FNM_PERIOD, flags);
# endif  /* mbstate_t and mbsrtowcs or _LIBC.  */
}

#endif	/* _LIBC or not __GNU_LIBRARY__.  */
