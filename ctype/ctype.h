/* Copyright (C) 1991,92,93,95,96,97,98,99,2001,02
   	Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/*
 *	ISO C99 Standard 7.4: Character handling	<ctype.h>
 */

#ifndef	_CTYPE_H
#define	_CTYPE_H	1

#include <features.h>
#include <bits/types.h>

__BEGIN_DECLS

#ifndef _ISbit
/* These are all the characteristics of characters.
   If there get to be more than 16 distinct characteristics,
   many things must be changed that use `unsigned short int's.

   The characteristics are stored always in network byte order (big
   endian).  We define the bit value interpretations here dependent on the
   machine's byte order.  */

# include <endian.h>
# if __BYTE_ORDER == __BIG_ENDIAN
#  define _ISbit(bit)	(1 << (bit))
# else /* __BYTE_ORDER == __LITTLE_ENDIAN */
#  define _ISbit(bit)	((bit) < 8 ? ((1 << (bit)) << 8) : ((1 << (bit)) >> 8))
# endif

enum
{
  _ISupper = _ISbit (0),	/* UPPERCASE.  */
  _ISlower = _ISbit (1),	/* lowercase.  */
  _ISalpha = _ISbit (2),	/* Alphabetic.  */
  _ISdigit = _ISbit (3),	/* Numeric.  */
  _ISxdigit = _ISbit (4),	/* Hexadecimal numeric.  */
  _ISspace = _ISbit (5),	/* Whitespace.  */
  _ISprint = _ISbit (6),	/* Printing.  */
  _ISgraph = _ISbit (7),	/* Graphical.  */
  _ISblank = _ISbit (8),	/* Blank (usually SPC and TAB).  */
  _IScntrl = _ISbit (9),	/* Control character.  */
  _ISpunct = _ISbit (10),	/* Punctuation.  */
  _ISalnum = _ISbit (11)	/* Alphanumeric.  */
};
#endif /* ! _ISbit  */

#define	__isascii(c)	(((c) & ~0x7f) == 0)	/* If C is a 7 bit value.  */
#define	__toascii(c)	((c) & 0x7f)		/* Mask off high bits.  */

#define	__exctype(name)	extern int name (int) __THROW

__BEGIN_NAMESPACE_STD

/* The following names are all functions:
     int isCHARACTERISTIC(int c);
   which return nonzero iff C has CHARACTERISTIC.
   For the meaning of the characteristic names, see the `enum' above.  */
__exctype (isalnum);
__exctype (isalpha);
__exctype (iscntrl);
__exctype (isdigit);
__exctype (islower);
__exctype (isgraph);
__exctype (isprint);
__exctype (ispunct);
__exctype (isspace);
__exctype (isupper);
__exctype (isxdigit);


/* Return the lowercase version of C.  */
extern int tolower (int __c) __THROW;

/* Return the uppercase version of C.  */
extern int toupper (int __c) __THROW;

__END_NAMESPACE_STD


/* ISO C99 introduced one new function.  */
#ifdef	__USE_ISOC99
__BEGIN_NAMESPACE_C99

__exctype (isblank);

__END_NAMESPACE_C99
#endif

#ifdef __USE_GNU
/* Test C for a set of character classes according to MASK.  */
extern int isctype (int __c, int __mask) __THROW;
#endif

#if defined __USE_SVID || defined __USE_MISC || defined __USE_XOPEN

/* Return nonzero iff C is in the ASCII set
   (i.e., is no more than 7 bits wide).  */
extern int isascii (int __c) __THROW;

/* Return the part of C that is in the ASCII set
   (i.e., the low-order 7 bits of C).  */
extern int toascii (int __c) __THROW;

/* These are the same as `toupper' and `tolower' except that they do not
   check the argument for being in the range of a `char'.  */
__exctype (_toupper);
__exctype (_tolower);
#endif /* Use SVID or use misc.  */

/* This code is needed for the optimized mapping functions.  */
#define __tobody(c, f, a, args) \
  (__extension__							      \
   ({ int __res;							      \
      if (sizeof (c) > 1)						      \
	{								      \
	  if (__builtin_constant_p (c))					      \
	    {								      \
	      int __c = (c);						      \
	      __res = __c < -128 || __c > 255 ? __c : (a)[__c];		      \
	    }								      \
	  else								      \
	    __res = f args;						      \
	}								      \
      else								      \
	__res = (a)[(int) (c)];						      \
      __res; }))

#if !defined __NO_CTYPE && !defined __cplusplus
# if defined __USE_SVID || defined __USE_MISC || defined __USE_XOPEN
#  define isascii(c)	__isascii (c)
#  define toascii(c)	__toascii (c)
# endif
#endif /* Not __NO_CTYPE.  */


#ifdef __USE_GNU
/* The concept of one static locale per category is not very well
   thought out.  Many applications will need to process its data using
   information from several different locales.  Another application is
   the implementation of the internationalization handling in the
   upcoming ISO C++ standard library.  To support this another set of
   the functions using locale data exist which have an additional
   argument.

   Attention: all these functions are *not* standardized in any form.
   This is a proof-of-concept implementation.  */

/* Structure for reentrant locale using functions.  This is an
   (almost) opaque type for the user level programs.  */
# include <xlocale.h>

/* These definitions are similar to the ones above but all functions
   take as an argument a handle for the locale which shall be used.  */
#  define __isctype_l(c, type, locale) \
  ((locale)->__ctype_b[(int) (c)] & (unsigned short int) type)

# define __exctype_l(name) 						      \
  extern int name (int, __locale_t) __THROW

/* The following names are all functions:
     int isCHARACTERISTIC(int c, locale_t *locale);
   which return nonzero iff C has CHARACTERISTIC.
   For the meaning of the characteristic names, see the `enum' above.  */
__exctype_l (isalnum_l);
__exctype_l (isalpha_l);
__exctype_l (iscntrl_l);
__exctype_l (isdigit_l);
__exctype_l (islower_l);
__exctype_l (isgraph_l);
__exctype_l (isprint_l);
__exctype_l (ispunct_l);
__exctype_l (isspace_l);
__exctype_l (isupper_l);
__exctype_l (isxdigit_l);

__exctype_l (isblank_l);


/* Return the lowercase version of C in locale L.  */
extern int __tolower_l (int __c, __locale_t __l) __THROW;
extern int tolower_l (int __c, __locale_t __l) __THROW;

/* Return the uppercase version of C.  */
extern int __toupper_l (int __c, __locale_t __l) __THROW;
extern int toupper_l (int __c, __locale_t __l) __THROW;

# if __GNUC__ >= 2 && defined __OPTIMIZE__ && !defined __cplusplus
#  define __tolower_l(c, locale) \
  __tobody (c, __tolower_l, (locale)->__ctype_tolower, (c, locale))
#  define __toupper_l(c, locale) \
  __tobody (c, __toupper_l, (locale)->__ctype_toupper, (c, locale))
#  define tolower_l(c, locale)	__tolower_l ((c), (locale))
#  define toupper_l(c, locale)	__toupper_l ((c), (locale))
# endif	/* Optimizing gcc */


# ifndef __NO_CTYPE
#  define __isalnum_l(c,l)	__isctype_l((c), _ISalnum, (l))
#  define __isalpha_l(c,l)	__isctype_l((c), _ISalpha, (l))
#  define __iscntrl_l(c,l)	__isctype_l((c), _IScntrl, (l))
#  define __isdigit_l(c,l)	__isctype_l((c), _ISdigit, (l))
#  define __islower_l(c,l)	__isctype_l((c), _ISlower, (l))
#  define __isgraph_l(c,l)	__isctype_l((c), _ISgraph, (l))
#  define __isprint_l(c,l)	__isctype_l((c), _ISprint, (l))
#  define __ispunct_l(c,l)	__isctype_l((c), _ISpunct, (l))
#  define __isspace_l(c,l)	__isctype_l((c), _ISspace, (l))
#  define __isupper_l(c,l)	__isctype_l((c), _ISupper, (l))
#  define __isxdigit_l(c,l)	__isctype_l((c), _ISxdigit, (l))

#  define __isblank_l(c,l)	__isctype_l((c), _ISblank, (l))

#  if defined __USE_SVID || defined __USE_MISC || defined __USE_XOPEN
#   define __isascii_l(c,l)	((l), __isascii (c))
#   define __toascii_l(c,l)	((l), __toascii (c))
#  endif

#  define isalnum_l(c,l)	__isalnum_l ((c), (l))
#  define isalpha_l(c,l)	__isalpha_l ((c), (l))
#  define iscntrl_l(c,l)	__iscntrl_l ((c), (l))
#  define isdigit_l(c,l)	__isdigit_l ((c), (l))
#  define islower_l(c,l)	__islower_l ((c), (l))
#  define isgraph_l(c,l)	__isgraph_l ((c), (l))
#  define isprint_l(c,l)	__isprint_l ((c), (l))
#  define ispunct_l(c,l)	__ispunct_l ((c), (l))
#  define isspace_l(c,l)	__isspace_l ((c), (l))
#  define isupper_l(c,l)	__isupper_l ((c), (l))
#  define isxdigit_l(c,l)	__isxdigit_l ((c), (l))

#  define isblank_l(c,l)	__isblank_l ((c), (l))

#  if defined __USE_SVID || defined __USE_MISC || defined __USE_XOPEN
#   define isascii_l(c,l)	__isascii_l ((c), (l))
#   define toascii_l(c,l)	__toascii_l ((c), (l))
#  endif

# endif /* Not __NO_CTYPE.  */

#endif /* Use GNU.  */

__END_DECLS

#endif /* ctype.h  */
