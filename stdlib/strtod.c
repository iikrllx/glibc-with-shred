/* Read decimal floating point numbers.
Copyright (C) 1995 Free Software Foundation, Inc.
Contributed by Ulrich Drepper.

This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.	 If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/* Configuration part.  These macros are defined by `strtold.c' and `strtof.c'
   to produce the `long double' and `float' versions of the reader.  */
#ifndef FLOAT
#define	FLOAT		double
#define	FLT		DBL
#define	STRTOF		strtod
#define	MPN2FLOAT	__mpn_construct_double
#define	FLOAT_HUGE_VAL	HUGE_VAL
#endif
/* End of configuration part.  */

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <localeinfo.h>
#include <math.h>
#include <stdlib.h>
#include "../stdio/gmp.h"
#include "../stdio/gmp-impl.h"
#include <gmp-mparam.h>
#include "../stdio/longlong.h"
#include "../stdio/fpioconst.h"

/* #define NDEBUG 1 */
#include <assert.h>


/* Constants we need from float.h; select the set for the FLOAT precision.  */
#define MANT_DIG	PASTE(FLT,_MANT_DIG)
#define	MAX_EXP		PASTE(FLT,_MAX_EXP)
#define	MIN_EXP		PASTE(FLT,_MIN_EXP)
#define MAX_10_EXP	PASTE(FLT,_MAX_10_EXP)
#define MIN_10_EXP	PASTE(FLT,_MIN_10_EXP)
#define	MAX_10_EXP_LOG	PASTE(FLT,_MAX_10_EXP_LOG)

/* Extra macros required to get FLT expanded before the pasting.  */
#define PASTE(a,b)	PASTE1(a,b)
#define PASTE1(a,b)	a##b

/* Function to construct a floating point number from an MP integer
   containing the fraction bits, a base 2 exponent, and a sign flag.  */
extern FLOAT MPN2FLOAT (mp_srcptr mpn, int exponent, int negative);

/* Definitions according to limb size used.  */
#if	BITS_PER_MP_LIMB == 32
#  define MAX_DIG_PER_LIMB	9
#  define MAX_FAC_PER_LIMB	1000000000L
#elif	BITS_PER_MP_LIMB == 64
#  define MAX_DIG_PER_LIMB	19
#  define MAX_FAC_PER_LIMB	10000000000000000000L
#else
#  error "mp_limb size " BITS_PER_MP_LIMB "not accounted for"	
#endif


/* Local data structure.  */
static const mp_limb _tens_in_limb[MAX_DIG_PER_LIMB] =
{    0,                  10,                100,
     1000,               10000,             100000,
     1000000,            10000000,          100000000
#if BITS_PER_MP_LIMB > 32
   , 1000000000,         10000000000,       100000000000,
     1000000000000,      10000000000000,    100000000000000,
     1000000000000000,   10000000000000000, 100000000000000000,
     1000000000000000000
#endif
#if BITS_PER_MP_LIMB > 64
  #error "Need to expand tens_in_limb table to" MAX_DIG_PER_LIMB
#endif
};

#ifndef	howmany
#define	howmany(x,y)		(((x)+((y)-1))/(y))
#endif
#define SWAP(x, y)		({ typeof(x) _tmp = x; x = y; y = _tmp; })

#define NDIG			(MAX_10_EXP - MIN_10_EXP + 2 * MANT_DIG)
#define	RETURN_LIMB_SIZE		howmany (MANT_DIG, BITS_PER_MP_LIMB)

#define RETURN(val,end) \
	do { if (endptr != 0) *endptr = (char *) end; return val; } while (0)

/* Maximum size necessary for mpn integers to hold floating point numbers.  */ 
#define	MPNSIZE		(howmany (MAX_EXP + MANT_DIG, BITS_PER_MP_LIMB) + 1)
/* Declare an mpn integer variable that big.  */
#define	MPN_VAR(name)	mp_limb name[MPNSIZE]; mp_size_t name##size
/* Copy an mpn integer value.  */
#define MPN_ASSIGN(dst, src) \
	memcpy (dst, src, (dst##size = src##size) * sizeof (mp_limb))


/* Return a floating point number of the needed type according to the given
   multi-precision number after possible rounding.  */
static inline FLOAT
round_and_return (mp_limb *retval, int exponent, int negative,
		  mp_limb round_limb, mp_size_t round_bit, int more_bits)
{
  if (exponent < MIN_EXP)
    {
      mp_size_t shift = MIN_EXP - 1 - exponent;

      if (shift >= MANT_DIG)
	{
	  errno = EDOM;
	  return 0.0;
	}

      more_bits |= (round_limb & ((1 << round_bit) - 1)) != 0;
      if (shift >= BITS_PER_MP_LIMB)
	{
	  round_limb = retval[(shift - 1) / BITS_PER_MP_LIMB];
	  round_bit = (shift - 1) % BITS_PER_MP_LIMB;
#if RETURN_LIMB_SIZE <= 2
	  assert (RETURN_LIMB_SIZE == 2);
	  more_bits |= retval[0] != 0;
	  retval[0] = retval[1];
	  retval[1] = 0;
#else
	  int disp = shift / BITS_PER_MP_LIMB;
	  int i = 0;
	  while (retval[i] == 0 && i < disp)
	    ++i;
	  more_bits |= i < disp;
	  for (i = disp; i < RETURN_LIMB_SIZE; ++i)
	    retval[i - disp] = retval[i];
	  MPN_ZERO (&retval[RETURN_LIMB_SIZE - disp], disp);
#endif
	  shift %= BITS_PER_MP_LIMB;
	}
      else
	{
          round_limb = retval[0];
          round_bit = shift - 1;
	}
      (void) __mpn_rshift (retval, retval, RETURN_LIMB_SIZE, shift);
      exponent = MIN_EXP - 2;
    }

  if ((round_limb & (1 << round_bit)) != 0 &&
      (more_bits || (retval[0] & 1) != 0 ||
       (round_limb & ((1 << round_bit) - 1)) != 0))
    {
      mp_limb cy = __mpn_add_1 (retval, retval, RETURN_LIMB_SIZE, 1);
      if (cy || (retval[RETURN_LIMB_SIZE - 1]
		 & (1 << (MANT_DIG % BITS_PER_MP_LIMB))) != 0)
	{
	  ++exponent;
	  (void) __mpn_rshift (retval, retval, RETURN_LIMB_SIZE, 1);
	  retval[RETURN_LIMB_SIZE - 1] |= 1 << (MANT_DIG % BITS_PER_MP_LIMB);
	}
    }

  if (exponent > MAX_EXP)
    return negative ? -FLOAT_HUGE_VAL : FLOAT_HUGE_VAL;

  return MPN2FLOAT (retval, exponent, negative);
}


/* Read a multi-precision integer starting at STR with exactly DIGCNT digits
   into N.  Return the size of the number limbs in NSIZE at the first
   character od the string that is not part of the integer as the function
   value.  If the EXPONENT is small enough to be taken as an additional
   factor for the resulting number (see code) multiply by it.  */
static inline const char *
str_to_mpn (const char *str, int digcnt, mp_limb *n, mp_size_t *nsize,
	    int *exponent)
{
  /* Number of digits for actual limb.  */
  int cnt = 0;
  mp_limb low = 0;
  mp_limb base;

  *nsize = 0;
  assert (digcnt > 0);
  do
    {
      if (cnt == MAX_DIG_PER_LIMB)
	{
	  if (*nsize == 0)
	    n[0] = low;
	  else
	    {
	      mp_limb cy;
	      cy = __mpn_mul_1 (n, n, *nsize, MAX_FAC_PER_LIMB);
	      cy += __mpn_add_1 (n, n, *nsize, low);
	      if (cy != 0)
		n[*nsize] = cy;
	    }
	  ++(*nsize);
	  cnt = 0;
	  low = 0;
	}

      /* There might be thousands separators or radix characters in the string.
	 But these all can be ignored because we know the format of the number
	 is correct and we have an exact number of characters to read.  */
      while (!isdigit (*str))
	++str;
      low = low * 10 + *str++ - '0';
      ++cnt;
    }
  while (--digcnt > 0);

  if (*exponent > 0 && cnt + *exponent <= MAX_DIG_PER_LIMB)
    {
      low *= _tens_in_limb[*exponent];
      base = _tens_in_limb[cnt + *exponent];
      *exponent = 0;
    }
  else
    base = _tens_in_limb[cnt];

  if (*nsize == 0)
    {
      n[0] = low;
      *nsize = 1;
    }
  else
    {
      mp_limb cy;
      cy = __mpn_mul_1 (n, n, *nsize, base);
      cy += __mpn_add_1 (n, n, *nsize, low);
      if (cy != 0)
	n[(*nsize)++] = cy;
    }
  return str;
}


/* Shift {PTR, SIZE} COUNT bits to the left, and fill the vacated bits
   with the COUNT most significant bits of LIMB.

   Tege doesn't like this function so I have to write it here myself. :)
   --drepper */
static inline void
__mpn_lshift_1 (mp_limb *ptr, mp_size_t size, unsigned int count, mp_limb limb)
{
  if (count == BITS_PER_MP_LIMB)
    {
      /* Optimize the case of shifting by exactly a word:
	 just copy words, with no actual bit-shifting.  */
      mp_size_t i;
      for (i = size - 1; i > 0; --i)
	ptr[i] = ptr[i - 1];
      ptr[0] = limb;
    }
  else
    {
      (void) __mpn_lshift (ptr, ptr, size, count);
      ptr[0] |= limb >> (BITS_PER_MP_LIMB - count);
    }
}


/* Return a floating point number with the value of the given string NPTR.
   Set *ENDPTR to the character after the last used one.  If the number is
   smaller than the smallest representable number, set `errno' to ERANGE and
   return 0.0.  If the number is too big to be represented, set `errno' to
   ERANGE and return HUGE_VAL with the approriate sign.  */
FLOAT
STRTOF (nptr, endptr)
    const char *nptr;
    char **endptr;
{
  int negative;			/* The sign of the number.  */
  MPN_VAR (num);		/* MP representation of the number.  */
  int exponent;			/* Exponent of the number.  */

  /* When we have to compute fractional digits we form a fraction with a
     second multi-precision number (and we sometimes need a second for
     temporary results).  */
  MPN_VAR (den);

  /* Representation for the return value.  */
  mp_limb retval[RETURN_LIMB_SIZE];
  /* Number of bits currently in result value.  */
  int bits;

  /* Running pointer after the last character processed in the string.  */
  const char *cp;
  /* Start of significant part of the number.  */
  const char *startp;
  /* Points at the character following the integer and fractional digits.  */
  const char *expp;
  /* Total number of digit and number of digits in integer part.  */
  int dig_no, int_no;
  /* Contains the last character read.  */
  char c;

  /* The radix character of the current locale.  */
  wchar_t decimal;
#ifdef	USE_GROUPING
  /* The thousands character of the current locale.  */
  wchar_t thousands;
  /* The numeric grouping specification of the current locale,
     in the format described in <locale.h>.  */
  const char *grouping;

  /* Check the grouping of the integer part at [BEGIN,END).
     Return zero iff a separator is found out of place.  */
  int grouping_ok (const char *begin, const char *end)
    {
      if (grouping)
	while (end > begin)
	  {
	    const char *p = end;
	    do
	      --p;
	    while (*p != thousands && p > begin);
	    if (end - 1 - p != *grouping++)
	      return 0;		/* Wrong number of digits in this group.  */
	    end = p;		/* Correct group; trim it off the end.  */

	    if (*grouping == 0)
	      --grouping;	/* Same grouping repeats in next iteration.  */
	    else if (*grouping == CHAR_MAX || *grouping < 0)
	      {
		/* No further grouping allowed.  */
		while (end > begin)
		  if (*--end == thousands)
		    return 0;
	      }
	  }
      return 1;
    }
  /* Return with no conversion if the grouping of [STARTP,CP) is bad.  */
#define	CHECK_GROUPING if (! grouping_ok (startp, cp)) RETURN (0.0, nptr); else

  grouping = _numeric_info->grouping; /* Cache the grouping info array.  */
  if (*grouping <= 0 || *grouping == CHAR_MAX)
    grouping = NULL;
  else
    {
      /* Figure out the thousands seperator character.  */
      if (mbtowc (&thousands_sep, _numeric_info->thousands_sep,
		  strlen (_numeric_info->thousands_sep)) <= 0)
	thousands = (wchar_t) *_numeric_info->thousands_sep;
      if (thousands == L'\0')
	grouping = NULL;
    }
#else
#define	grouping	NULL
#define	thousands	L'\0'
#define	CHECK_GROUPING	((void) 0)
#endif

  /* Find the locale's decimal point character.  */
  if (mbtowc (&decimal, _numeric_info->decimal_point,
	      strlen (_numeric_info->decimal_point)) <= 0)
    decimal = (wchar_t) *_numeric_info->decimal_point;


  /* Prepare number representation.  */
  exponent = 0;
  negative = 0;
  bits = 0;

  /* Parse string to get maximal legal prefix.  We need the number of
     characters of the interger part, the fractional part and the exponent.  */
  cp = nptr - 1;
  /* Ignore leading white space.  */
  do
    c = *++cp;
  while (isspace (c));

  /* Get sign of the result.  */
  if (c == '-')
    {
      negative = 1;
      c = *++cp;
    }
  else if (c == '+')
    c = *++cp;

  /* Return 0.0 if no legal string is found.
     No character is used even if a sign was found.  */
  if (!isdigit (c) && (c != decimal || !isdigit (cp[1])))
    RETURN (0.0, nptr);

  /* Record the start of the digits, in case we will check their grouping.  */
  startp = cp;

  /* Ignore leading zeroes.  This helps us to avoid useless computations.  */
  while (c == '0' || (thousands != L'\0' && c == thousands))
    c = *++cp;

  CHECK_GROUPING;

  /* If no other digit but a '0' is found the result is 0.0.
     Return current read pointer.  */
  if (!isdigit (c) && c != decimal)
    RETURN (0.0, cp);

  /* Remember first significant digit and read following characters until the
     decimal point, exponent character or any non-FP number character.  */
  startp = cp;
  dig_no = 0;
  while (dig_no < NDIG ||
	 /* If parsing grouping info, keep going past useful digits
	    so we can check all the grouping separators.  */
	 grouping)
    {
      if (isdigit (c))
	++dig_no;
      else if (thousands == L'\0' || c != thousands)
	/* Not a digit or separator: end of the integer part.  */
	break;
      c = *++cp;
    }

  CHECK_GROUPING;

  if (dig_no >= NDIG)
    /* Too many digits to be representable.  Assigning this to EXPONENT
       allows us to read the full number but return HUGE_VAL after parsing.  */
    exponent = MAX_10_EXP;

  /* We have the number digits in the integer part.  Whether these are all or
     any is really a fractional digit will be decided later.  */
  int_no = dig_no;

  /* Read the fractional digits.  */
  if (c == decimal)
    {
      if (isdigit (cp[1]))
	{
	  ++cp;
	  do
	    {
	      ++dig_no;
	      c = *++cp;
	    }
	  while (isdigit (c));
	}
    }

  /* Remember start of exponent (if any).  */
  expp = cp;

  /* Read exponent.  */
  if (tolower (c) == 'e')
    {
      int exp_negative = 0;

      c = *++cp;
      if (c == '-')
	{
	  exp_negative = 1;
	  c = *++cp;
	}
      else if (c == '+')
	c = *++cp;

      if (isdigit (c))
	{
	  do
	    {
	      if ((!exp_negative && exponent * 10 + int_no > MAX_10_EXP)
		  || (exp_negative
		      && exponent * 10 + int_no > -MIN_10_EXP + MANT_DIG))
		/* The exponent is too large/small to represent a valid
		   number.  */
		{
	 	  FLOAT retval;

		  /* Overflow or underflow.  */
		  errno = ERANGE;
		  retval = (exp_negative ? 0.0 :
			    negative ? -FLOAT_HUGE_VAL : FLOAT_HUGE_VAL);

		  /* Accept all following digits as part of the exponent.  */
		  do
		    ++cp;
		  while (isdigit (*cp));

		  RETURN (retval, cp);
		  /* NOTREACHED */
		}

	      exponent *= 10;
	      exponent += c - '0';
	      c = *++cp;
	    }
	  while (isdigit (c));
	}
      else
	cp = expp;

      if (exp_negative)
	exponent = -exponent;
    }

  /* We don't want to have to work with trailing zeroes after the radix.  */
  if (dig_no > int_no)
    {
      while (expp[-1] == '0')
	{
	  --expp;
	  --dig_no;
	}
      assert (dig_no >= int_no);
    }

  /* The whole string is parsed.  Store the address of the next character.  */
  if (endptr)
    *endptr = (char *) cp;

  if (dig_no == 0)
    return 0.0;

  /* Now we have the number of digits in total and the integer digits as well
     as the exponent and its sign.  We can decide whether the read digits are
     really integer digits or belong to the fractional part; i.e. we normalize
     123e-2 to 1.23.  */
  {
    register int incr = exponent < 0 ? MAX (-int_no, exponent)
				     : MIN (dig_no - int_no, exponent);
    int_no += incr;
    exponent -= incr;
  }

  if (int_no + exponent > MAX_10_EXP)
    {
      errno = ERANGE;
      return negative ? -FLOAT_HUGE_VAL : FLOAT_HUGE_VAL;
    }

  if (int_no - dig_no + exponent < MIN_10_EXP - MANT_DIG)
    {
      errno = ERANGE;
      return 0.0;
    }	

  if (int_no > 0)
    {
      /* Read the integer part as a multi-precision number to NUM.  */
      startp = str_to_mpn (startp, int_no, num, &numsize, &exponent);

      if (exponent > 0)
	{
	  /* We now multiply the gained number by the given power of ten.  */
	  mp_limb *psrc = num;
	  mp_limb *pdest = den;
	  int expbit = 1;
	  const struct mp_power *ttab = &_fpioconst_pow10[0];

	  assert (exponent < (1 << (MAX_10_EXP_LOG + 1)));
	  do
	    {
	      if ((exponent & expbit) != 0)
		{
		  mp_limb cy;
		  exponent ^= expbit;

		  /* FIXME: not the whole multiplication has to be done.
		     If we have the needed number of bits we only need the
		     information whether more non-zero bits follow.  */
		  if (numsize >= ttab->arraysize - 2)
		    cy = __mpn_mul (pdest, psrc, numsize,
				    &ttab->array[2], ttab->arraysize - 2);
		  else
		    cy = __mpn_mul (pdest, &ttab->array[2],
				    ttab->arraysize - 2,
				    psrc, numsize);
		  numsize += ttab->arraysize - 2;
		  if (cy == 0)
		    --numsize;
		  SWAP (psrc, pdest);
		}
	      expbit <<= 1;
	      ++ttab;
	    }
	  while (exponent != 0);

	  if (psrc == den)
	    memcpy (num, den, numsize * sizeof (mp_limb));
	}

      /* Determine how many bits of the result we already have.  */
      count_leading_zeros (bits, num[numsize - 1]);
      bits = numsize * BITS_PER_MP_LIMB - bits;

      /* We have already the first BITS bits of the result.  Together with
	 the information whether more non-zero bits follow this is enough
	 to determine the result.  */
      if (bits > MANT_DIG)
	{
	  const mp_size_t least_idx = (bits - MANT_DIG) / BITS_PER_MP_LIMB;
	  const mp_size_t least_bit = (bits - MANT_DIG) % BITS_PER_MP_LIMB;
	  const mp_size_t round_idx = least_bit == 0 ? least_idx - 1
						     : least_idx;
	  const mp_size_t round_bit = least_bit == 0 ? BITS_PER_MP_LIMB - 1
						     : least_idx - 1;
	  int i;

	  if (least_bit == 0)
	    memcpy (retval, &num[least_idx],
		    RETURN_LIMB_SIZE * sizeof (mp_limb));
	  else
	    (void) __mpn_rshift (retval, &num[least_idx],
				 numsize - least_idx + 1, least_bit);

	  /* Check whether any limb beside the ones in RETVAL are non-zero.  */
	  for (i = 0; num[i] == 0; ++i)
	    ;

	  return round_and_return (retval, bits - 1, negative,
				   num[round_idx], round_bit,
				   int_no < dig_no || i < round_idx);
	  /* NOTREACHED */
	}
      else if (dig_no == int_no)
	{
	  const mp_size_t target_bit = (MANT_DIG - 1) % BITS_PER_MP_LIMB;
	  const mp_size_t is_bit = (bits - 1) % BITS_PER_MP_LIMB;

	  if (target_bit == is_bit)
	    {
	      memcpy (&retval[RETURN_LIMB_SIZE - numsize], num,
		      numsize * sizeof (mp_limb));
	      /* FIXME: the following loop can be avoided if we assume a
		 maximal MANT_DIG value.  */
	      MPN_ZERO (retval, RETURN_LIMB_SIZE - numsize);
	    }
	  else if (target_bit > is_bit)
	    {
	      (void) __mpn_lshift (&retval[RETURN_LIMB_SIZE - numsize],
				   num, numsize, target_bit - is_bit);
	      /* FIXME: the following loop can be avoided if we assume a
		 maximal MANT_DIG value.  */
	      MPN_ZERO (retval, RETURN_LIMB_SIZE - numsize);
	    }
	  else
	    {
	      mp_limb cy;
	      assert (numsize < RETURN_LIMB_SIZE);

	      cy = __mpn_rshift (&retval[RETURN_LIMB_SIZE - numsize],
				 num, numsize, is_bit - target_bit);
	      retval[RETURN_LIMB_SIZE - numsize - 1] = cy;
	      /* FIXME: the following loop can be avoided if we assume a
		 maximal MANT_DIG value.  */
	      MPN_ZERO (retval, RETURN_LIMB_SIZE - numsize - 1);
	    }

	  return round_and_return (retval, bits - 1, negative, 0, 0, 0);
	  /* NOTREACHED */
	}

      /* Store the bits we already have.  */
      memcpy (retval, num, numsize * sizeof (mp_limb));
#if RETURN_LIMB_SIZE > 1
      if (numsize < RETURN_LIMB_SIZE)
        retval[numsize] = 0;
#endif
    }

  /* We have to compute at least some of the fractional digits.  */
  {
    /* We construct a fraction and the result of the division gives us
       the needed digits.  The denominator is 1.0 multiplied by the
       exponent of the lowest digit; i.e. 0.123 gives 123 / 1000 and
       123e6 gives 123 / 1000000.  */

    int expbit;
    int cnt;
    mp_limb cy;
    mp_limb *psrc = den;
    mp_limb *pdest = num;
    int neg_exp = dig_no - int_no - exponent;
    const struct mp_power *ttab = &_fpioconst_pow10[0];

    assert (dig_no > int_no && exponent <= 0);

    /* Construct the denominator.  */
    densize = 0;
    expbit = 1;
    do
      {
	if ((neg_exp & expbit) != 0)
	  {
	    mp_limb cy;
	    neg_exp ^= expbit;

	    if (densize == 0)
	      memcpy (psrc, &ttab->array[2],
		      (densize = ttab->arraysize - 2) * sizeof (mp_limb));
	    else
	      {
		cy = __mpn_mul (pdest, &ttab->array[2], ttab->arraysize - 2,
				psrc, densize);
		densize += ttab->arraysize - 2;
		if (cy == 0)
		  --densize;
		SWAP (psrc, pdest);
	      }
	  }
	expbit <<= 1;
	++ttab;
      }
    while (neg_exp != 0);

    if (psrc == num)
      memcpy (den, num, densize * sizeof (mp_limb));

    /* Read the fractional digits from the string.  */ 
    (void) str_to_mpn (startp, dig_no - int_no, num, &numsize, &exponent);


    /* We now have to shift both numbers so that the highest bit in the
       denominator is set.  In the same process we copy the numerator to
       a high place in the array so that the division constructs the wanted
       digits.  This is done by a "quasi fix point" number representation.

       num:   ddddddddddd . 0000000000000000000000
              |--- m ---|
       den:                            ddddddddddd      n >= m
                                       |--- n ---|
     */

    count_leading_zeros (cnt, den[densize - 1]);

    (void) __mpn_lshift (den, den, densize, cnt);
    cy = __mpn_lshift (num, num, numsize, cnt);
    if (cy != 0)
      num[numsize++] = cy;

    /* Now we are ready for the division.  But it is not necessary to
       do a full multi-precision division because we only need a small
       number of bits for the result.  So we do not use __mpn_divmod
       here but instead do the division here by hand and stop whenever
       the needed number of bits is reached.  The code itself comes
       from the GNU MP Library by Torbj\"orn Granlund.  */

    exponent = bits;

    switch (densize)
      {
      case 1:
	{
	  mp_limb d, n, quot;
	  int used = 0;

	  n = num[0];
	  d = den[0];
	  assert (numsize == 1 && n < d);

	  do
	    {
	      udiv_qrnnd (quot, n, n, 0, d);

#define got_limb							      \
	      if (bits == 0)						      \
		{							      \
		  register int cnt;					      \
		  if (quot == 0)					      \
		    cnt = BITS_PER_MP_LIMB;				      \
		  else							      \
		    count_leading_zeros (cnt, quot);			      \
		  exponent -= cnt;					      \
		  if (BITS_PER_MP_LIMB - cnt > MANT_DIG)		      \
		    {							      \
		      used = cnt + MANT_DIG;				      \
		      retval[0] = quot >> (BITS_PER_MP_LIMB - used);	      \
		      bits -= BITS_PER_MP_LIMB - used;			      \
		    }							      \
		  else							      \
		    {							      \
		      /* Note that we only clear the second element.  */      \
		      retval[1] = 0;					      \
		      retval[0] = quot;					      \
		      bits -= cnt;					      \
		    }							      \
		}							      \
	      else if (bits + BITS_PER_MP_LIMB <= MANT_DIG)		      \
		__mpn_lshift_1 (retval, RETURN_LIMB_SIZE, BITS_PER_MP_LIMB,    \
				quot);					      \
	      else							      \
		{							      \
		  used = MANT_DIG - bits;				      \
		  if (used > 0)						      \
		    __mpn_lshift_1 (retval, RETURN_LIMB_SIZE, used, quot);     \
		}							      \
	      bits += BITS_PER_MP_LIMB

              got_limb;
	    }
	  while (bits <= MANT_DIG);

	  return round_and_return (retval, exponent - 1, negative,
				   quot, BITS_PER_MP_LIMB - 1 - used,
				   n != 0);
	}
      case 2:
	{
	  mp_limb d0, d1, n0, n1;
	  mp_limb quot = 0;
	  int used = 0;

	  d0 = den[0];
	  d1 = den[1];

	  if (numsize < densize)
	    {
	      if (bits <= 0)
		exponent -= BITS_PER_MP_LIMB;
	      else
		{
		  if (bits + BITS_PER_MP_LIMB <= MANT_DIG)
		    __mpn_lshift_1 (retval, RETURN_LIMB_SIZE,
				    BITS_PER_MP_LIMB, 0);
		  else
		    {
		      used = MANT_DIG - bits;
		      if (used > 0)
			__mpn_lshift_1 (retval, RETURN_LIMB_SIZE, used, 0);
		    }
		  bits += BITS_PER_MP_LIMB;
		}
	      n1 = num[0];
	      n0 = 0;
	    }
	  else
	    {
	      n1 = num[1];
	      n0 = num[0];
	    }

	  while (bits <= MANT_DIG)
	    {
	      mp_limb r;

	      if (n1 == d1)
		{
		  /* QUOT should be either 111..111 or 111..110.  We need
		     special treatment of this rare case as normal division
		     would give overflow.  */
		  quot = ~(mp_limb) 0;

		  r = n0 + d1;
		  if (r < d1)	/* Carry in the addition?  */
		    {
		      add_ssaaaa (n1, n0, r - d0, 0, 0, d0);
		      goto have_quot;
		    }
		  n1 = d0 - (d0 != 0);
		  n0 = -d0;
		}
	      else
		{
		  udiv_qrnnd (quot, r, n1, n0, d1);
		  umul_ppmm (n1, n0, d0, quot);
		}

	    q_test:
	      if (n1 > r || (n1 == r && n0 > 0))
		{
		  /* The estimated QUOT was too large.  */
		  --quot;

		  sub_ddmmss (n1, n0, n1, n0, 0, d0);
		  r += d1;
		  if (r >= d1)	/* If not carry, test QUOT again.  */
		    goto q_test;
		}
	      sub_ddmmss (n1, n0, r, 0, n1, n0);

	    have_quot:
	      got_limb;
	    }
	    
	  return round_and_return (retval, exponent - 1, negative,
				   quot, BITS_PER_MP_LIMB - 1 - used,
				   n1 != 0 || n0 != 0);
	}
      default:
	{
	  int i;
	  mp_limb cy, dX, d1, n0, n1;
	  mp_limb quot = 0;
	  int used = 0;

	  dX = den[densize - 1];
	  d1 = den[densize - 2];

	  /* The division does not work if the upper limb of the two-limb
	     numerator is greater than the denominator.  */
	  if (num[numsize - 1] > dX)
	    num[numsize++] = 0;

	  if (numsize < densize)
	    {
	      mp_size_t empty = densize - numsize;

	      if (bits <= 0)
		{
		  register int i;
		  for (i = numsize; i > 0; --i)
		    num[i + empty] = num[i - 1];
		  MPN_ZERO (num, empty + 1);
		  exponent -= empty * BITS_PER_MP_LIMB;
		}
	      else
		{
		  if (bits + empty * BITS_PER_MP_LIMB <= MANT_DIG)
		    {
		      /* We make a difference here because the compiler
			 cannot optimize the `else' case that good and
			 this reflects all currently used FLOAT types
			 and GMP implementations.  */
		      register int i;
#if RETURN_LIMB_SIZE <= 2
		      assert (empty == 1);
		      __mpn_lshift_1 (retval, RETURN_LIMB_SIZE,
				      BITS_PER_MP_LIMB, 0);
#else
		      for (i = RETURN_LIMB_SIZE; i > empty; --i)
			retval[i] = retval[i - empty];
#endif
		      retval[1] = 0;
		      for (i = numsize; i > 0; --i)
			num[i + empty] = num[i - 1];
		      MPN_ZERO (num, empty + 1);
		    }
		  else
		    {
		      used = MANT_DIG - bits;
		      if (used >= BITS_PER_MP_LIMB)
			{
			  register int i;
			  (void) __mpn_lshift (&retval[used
						       / BITS_PER_MP_LIMB],
					       retval, RETURN_LIMB_SIZE,
					       used % BITS_PER_MP_LIMB);
			  for (i = used / BITS_PER_MP_LIMB; i >= 0; --i)
			    retval[i] = 0;
			}
		      else if (used > 0)
			__mpn_lshift_1 (retval, RETURN_LIMB_SIZE, used, 0);
		    }
		  bits += empty * BITS_PER_MP_LIMB;
		}
	    }
	  else
	    {
	      int i;
	      assert (numsize == densize);
	      for (i = numsize; i > 0; --i)
		num[i] = num[i - 1];
	    }

	  den[densize] = 0;
	  n0 = num[densize];

	  while (bits <= MANT_DIG)
	    {
	      if (n0 == dX)
		/* This might over-estimate QUOT, but it's probably not
		   worth the extra code here to find out.  */
		quot = ~(mp_limb) 0;
	      else
		{
		  mp_limb r;

		  udiv_qrnnd (quot, r, n0, num[densize - 1], dX);
		  umul_ppmm (n1, n0, d1, quot);

		  while (n1 > r || (n1 == r && n0 > num[densize - 2]))
		    {
		      --quot;
		      r += dX;
		      if (r < dX) /* I.e. "carry in previous addition?" */
			break;
		      n1 -= n0 < d1;
		      n0 -= d1;
		    }
		}

	      /* Possible optimization: We already have (q * n0) and (1 * n1)
		 after the calculation of QUOT.  Taking advantage of this, we
		 could make this loop make two iterations less.  */

	      cy = __mpn_submul_1 (num, den, densize + 1, quot);

	      if (num[densize] != cy)
		{
		  cy = __mpn_add_n (num, num, den, densize);
		  assert (cy != 0);
		  --quot;
		}
	      n0 = num[densize] = num[densize - 1];
	      for (i = densize - 1; i > 0; --i)
		num[i] = num[i - 1];

	      got_limb;
	    }

	  for (i = densize - 1; num[i] != 0 && i >= 0; --i)
	    ;
	  return round_and_return (retval, exponent - 1, negative,
				   quot, BITS_PER_MP_LIMB - 1 - used,
				   i >= 0);
	}
      }
  }

  /* NOTREACHED */
}
