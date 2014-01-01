/* Implementation of gamma function according to ISO C.
   Copyright (C) 1997-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <math.h>
#include <math_private.h>
#include <float.h>

/* Coefficients B_2k / 2k(2k-1) of x^-(2k-1) inside exp in Stirling's
   approximation to gamma function.  */

static const long double gamma_coeff[] =
  {
    0x1.5555555555555556p-4L,
    -0xb.60b60b60b60b60bp-12L,
    0x3.4034034034034034p-12L,
    -0x2.7027027027027028p-12L,
    0x3.72a3c5631fe46aep-12L,
    -0x7.daac36664f1f208p-12L,
    0x1.a41a41a41a41a41ap-8L,
    -0x7.90a1b2c3d4e5f708p-8L,
  };

#define NCOEFF (sizeof (gamma_coeff) / sizeof (gamma_coeff[0]))

/* Return gamma (X), for positive X less than 1766, in the form R *
   2^(*EXP2_ADJ), where R is the return value and *EXP2_ADJ is set to
   avoid overflow or underflow in intermediate calculations.  */

static long double
gammal_positive (long double x, int *exp2_adj)
{
  int local_signgam;
  if (x < 0.5L)
    {
      *exp2_adj = 0;
      return __ieee754_expl (__ieee754_lgammal_r (x + 1, &local_signgam)) / x;
    }
  else if (x <= 1.5L)
    {
      *exp2_adj = 0;
      return __ieee754_expl (__ieee754_lgammal_r (x, &local_signgam));
    }
  else if (x < 7.5L)
    {
      /* Adjust into the range for using exp (lgamma).  */
      *exp2_adj = 0;
      long double n = __ceill (x - 1.5L);
      long double x_adj = x - n;
      long double eps;
      long double prod = __gamma_productl (x_adj, 0, n, &eps);
      return (__ieee754_expl (__ieee754_lgammal_r (x_adj, &local_signgam))
	      * prod * (1.0L + eps));
    }
  else
    {
      long double eps = 0;
      long double x_eps = 0;
      long double x_adj = x;
      long double prod = 1;
      if (x < 13.0L)
	{
	  /* Adjust into the range for applying Stirling's
	     approximation.  */
	  long double n = __ceill (13.0L - x);
	  x_adj = x + n;
	  x_eps = (x - (x_adj - n));
	  prod = __gamma_productl (x_adj - n, x_eps, n, &eps);
	}
      /* The result is now gamma (X_ADJ + X_EPS) / (PROD * (1 + EPS)).
	 Compute gamma (X_ADJ + X_EPS) using Stirling's approximation,
	 starting by computing pow (X_ADJ, X_ADJ) with a power of 2
	 factored out.  */
      long double exp_adj = -eps;
      long double x_adj_int = __roundl (x_adj);
      long double x_adj_frac = x_adj - x_adj_int;
      int x_adj_log2;
      long double x_adj_mant = __frexpl (x_adj, &x_adj_log2);
      if (x_adj_mant < M_SQRT1_2l)
	{
	  x_adj_log2--;
	  x_adj_mant *= 2.0L;
	}
      *exp2_adj = x_adj_log2 * (int) x_adj_int;
      long double ret = (__ieee754_powl (x_adj_mant, x_adj)
			 * __ieee754_exp2l (x_adj_log2 * x_adj_frac)
			 * __ieee754_expl (-x_adj)
			 * __ieee754_sqrtl (2 * M_PIl / x_adj)
			 / prod);
      exp_adj += x_eps * __ieee754_logl (x);
      long double bsum = gamma_coeff[NCOEFF - 1];
      long double x_adj2 = x_adj * x_adj;
      for (size_t i = 1; i <= NCOEFF - 1; i++)
	bsum = bsum / x_adj2 + gamma_coeff[NCOEFF - 1 - i];
      exp_adj += bsum / x_adj;
      return ret + ret * __expm1l (exp_adj);
    }
}

long double
__ieee754_gammal_r (long double x, int *signgamp)
{
  u_int32_t es, hx, lx;

  GET_LDOUBLE_WORDS (es, hx, lx, x);

  if (__builtin_expect (((es & 0x7fff) | hx | lx) == 0, 0))
    {
      /* Return value for x == 0 is Inf with divide by zero exception.  */
      *signgamp = 0;
      return 1.0 / x;
    }
  if (__builtin_expect (es == 0xffffffff && ((hx & 0x7fffffff) | lx) == 0, 0))
    {
      /* x == -Inf.  According to ISO this is NaN.  */
      *signgamp = 0;
      return x - x;
    }
  if (__builtin_expect ((es & 0x7fff) == 0x7fff, 0))
    {
      /* Positive infinity (return positive infinity) or NaN (return
	 NaN).  */
      *signgamp = 0;
      return x + x;
    }
  if (__builtin_expect ((es & 0x8000) != 0, 0) && __rintl (x) == x)
    {
      /* Return value for integer x < 0 is NaN with invalid exception.  */
      *signgamp = 0;
      return (x - x) / (x - x);
    }

  if (x >= 1756.0L)
    {
      /* Overflow.  */
      *signgamp = 0;
      return LDBL_MAX * LDBL_MAX;
    }
  else if (x > 0.0L)
    {
      *signgamp = 0;
      int exp2_adj;
      long double ret = gammal_positive (x, &exp2_adj);
      return __scalbnl (ret, exp2_adj);
    }
  else if (x >= -LDBL_EPSILON / 4.0L)
    {
      *signgamp = 0;
      return 1.0f / x;
    }
  else
    {
      long double tx = __truncl (x);
      *signgamp = (tx == 2.0L * __truncl (tx / 2.0L)) ? -1 : 1;
      if (x <= -1766.0L)
	/* Underflow.  */
	return LDBL_MIN * LDBL_MIN;
      long double frac = tx - x;
      if (frac > 0.5L)
	frac = 1.0L - frac;
      long double sinpix = (frac <= 0.25L
			    ? __sinl (M_PIl * frac)
			    : __cosl (M_PIl * (0.5L - frac)));
      int exp2_adj;
      long double ret = M_PIl / (-x * sinpix
				 * gammal_positive (-x, &exp2_adj));
      return __scalbnl (ret, -exp2_adj);
    }
}
strong_alias (__ieee754_gammal_r, __gammal_r_finite)
