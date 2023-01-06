/* Compute x * y + z as ternary operation.
   Copyright (C) 2010-2023 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#define NO_MATH_REDIRECT
#include <float.h>
#include <math.h>
#include <fenv.h>
#include <ieee754.h>
#include <math-barriers.h>
#include <libm-alias-ldouble.h>
#include <tininess.h>

/* This implementation uses rounding to odd to avoid problems with
   double rounding.  See a paper by Boldo and Melquiond:
   http://www.lri.fr/~melquion/doc/08-tc.pdf  */

long double
__fmal (long double x, long double y, long double z)
{
  union ieee854_long_double u, v, w;
  int adjust = 0;
  u.d = x;
  v.d = y;
  w.d = z;
  if (__builtin_expect (u.ieee.exponent + v.ieee.exponent
			>= 0x7fff + IEEE854_LONG_DOUBLE_BIAS
			   - LDBL_MANT_DIG, 0)
      || __builtin_expect (u.ieee.exponent >= 0x7fff - LDBL_MANT_DIG, 0)
      || __builtin_expect (v.ieee.exponent >= 0x7fff - LDBL_MANT_DIG, 0)
      || __builtin_expect (w.ieee.exponent >= 0x7fff - LDBL_MANT_DIG, 0)
      || __builtin_expect (u.ieee.exponent + v.ieee.exponent
			   <= IEEE854_LONG_DOUBLE_BIAS + LDBL_MANT_DIG, 0))
    {
      /* If z is Inf, but x and y are finite, the result should be
	 z rather than NaN.  */
      if (w.ieee.exponent == 0x7fff
	  && u.ieee.exponent != 0x7fff
          && v.ieee.exponent != 0x7fff)
	return (z + x) + y;
      /* If z is zero and x are y are nonzero, compute the result
	 as x * y to avoid the wrong sign of a zero result if x * y
	 underflows to 0.  */
      if (z == 0 && x != 0 && y != 0)
	return x * y;
      /* If x or y or z is Inf/NaN, or if x * y is zero, compute as
	 x * y + z.  */
      if (u.ieee.exponent == 0x7fff
	  || v.ieee.exponent == 0x7fff
	  || w.ieee.exponent == 0x7fff
	  || x == 0
	  || y == 0)
	return x * y + z;
      /* If fma will certainly overflow, compute as x * y.  */
      if (u.ieee.exponent + v.ieee.exponent
	  > 0x7fff + IEEE854_LONG_DOUBLE_BIAS)
	return x * y;
      /* If x * y is less than 1/4 of LDBL_TRUE_MIN, neither the
	 result nor whether there is underflow depends on its exact
	 value, only on its sign.  */
      if (u.ieee.exponent + v.ieee.exponent
	  < IEEE854_LONG_DOUBLE_BIAS - LDBL_MANT_DIG - 2)
	{
	  int neg = u.ieee.negative ^ v.ieee.negative;
	  long double tiny = neg ? -0x1p-16445L : 0x1p-16445L;
	  if (w.ieee.exponent >= 3)
	    return tiny + z;
	  /* Scaling up, adding TINY and scaling down produces the
	     correct result, because in round-to-nearest mode adding
	     TINY has no effect and in other modes double rounding is
	     harmless.  But it may not produce required underflow
	     exceptions.  */
	  v.d = z * 0x1p65L + tiny;
	  if (TININESS_AFTER_ROUNDING
	      ? v.ieee.exponent < 66
	      : (w.ieee.exponent == 0
		 || (w.ieee.exponent == 1
		     && w.ieee.negative != neg
		     && w.ieee.mantissa1 == 0
		     && w.ieee.mantissa0 == 0x80000000)))
	    {
	      long double force_underflow = x * y;
	      math_force_eval (force_underflow);
	    }
	  return v.d * 0x1p-65L;
	}
      if (u.ieee.exponent + v.ieee.exponent
	  >= 0x7fff + IEEE854_LONG_DOUBLE_BIAS - LDBL_MANT_DIG)
	{
	  /* Compute 1p-64 times smaller result and multiply
	     at the end.  */
	  if (u.ieee.exponent > v.ieee.exponent)
	    u.ieee.exponent -= LDBL_MANT_DIG;
	  else
	    v.ieee.exponent -= LDBL_MANT_DIG;
	  /* If x + y exponent is very large and z exponent is very small,
	     it doesn't matter if we don't adjust it.  */
	  if (w.ieee.exponent > LDBL_MANT_DIG)
	    w.ieee.exponent -= LDBL_MANT_DIG;
	  adjust = 1;
	}
      else if (w.ieee.exponent >= 0x7fff - LDBL_MANT_DIG)
	{
	  /* Similarly.
	     If z exponent is very large and x and y exponents are
	     very small, adjust them up to avoid spurious underflows,
	     rather than down.  */
	  if (u.ieee.exponent + v.ieee.exponent
	      <= IEEE854_LONG_DOUBLE_BIAS + 2 * LDBL_MANT_DIG)
	    {
	      if (u.ieee.exponent > v.ieee.exponent)
		u.ieee.exponent += 2 * LDBL_MANT_DIG + 2;
	      else
		v.ieee.exponent += 2 * LDBL_MANT_DIG + 2;
	    }
	  else if (u.ieee.exponent > v.ieee.exponent)
	    {
	      if (u.ieee.exponent > LDBL_MANT_DIG)
		u.ieee.exponent -= LDBL_MANT_DIG;
	    }
	  else if (v.ieee.exponent > LDBL_MANT_DIG)
	    v.ieee.exponent -= LDBL_MANT_DIG;
	  w.ieee.exponent -= LDBL_MANT_DIG;
	  adjust = 1;
	}
      else if (u.ieee.exponent >= 0x7fff - LDBL_MANT_DIG)
	{
	  u.ieee.exponent -= LDBL_MANT_DIG;
	  if (v.ieee.exponent)
	    v.ieee.exponent += LDBL_MANT_DIG;
	  else
	    v.d *= 0x1p64L;
	}
      else if (v.ieee.exponent >= 0x7fff - LDBL_MANT_DIG)
	{
	  v.ieee.exponent -= LDBL_MANT_DIG;
	  if (u.ieee.exponent)
	    u.ieee.exponent += LDBL_MANT_DIG;
	  else
	    u.d *= 0x1p64L;
	}
      else /* if (u.ieee.exponent + v.ieee.exponent
		  <= IEEE854_LONG_DOUBLE_BIAS + LDBL_MANT_DIG) */
	{
	  if (u.ieee.exponent > v.ieee.exponent)
	    u.ieee.exponent += 2 * LDBL_MANT_DIG + 2;
	  else
	    v.ieee.exponent += 2 * LDBL_MANT_DIG + 2;
	  if (w.ieee.exponent <= 4 * LDBL_MANT_DIG + 6)
	    {
	      if (w.ieee.exponent)
		w.ieee.exponent += 2 * LDBL_MANT_DIG + 2;
	      else
		w.d *= 0x1p130L;
	      adjust = -1;
	    }
	  /* Otherwise x * y should just affect inexact
	     and nothing else.  */
	}
      x = u.d;
      y = v.d;
      z = w.d;
    }

  /* Ensure correct sign of exact 0 + 0.  */
  if (__glibc_unlikely ((x == 0 || y == 0) && z == 0))
    {
      x = math_opt_barrier (x);
      return x * y + z;
    }

  fenv_t env;
  feholdexcept (&env);
  fesetround (FE_TONEAREST);

  /* Multiplication m1 + m2 = x * y using Dekker's algorithm.  */
#define C ((1LL << (LDBL_MANT_DIG + 1) / 2) + 1)
  long double x1 = x * C;
  long double y1 = y * C;
  long double m1 = x * y;
  x1 = (x - x1) + x1;
  y1 = (y - y1) + y1;
  long double x2 = x - x1;
  long double y2 = y - y1;
  long double m2 = (((x1 * y1 - m1) + x1 * y2) + x2 * y1) + x2 * y2;

  /* Addition a1 + a2 = z + m1 using Knuth's algorithm.  */
  long double a1 = z + m1;
  long double t1 = a1 - z;
  long double t2 = a1 - t1;
  t1 = m1 - t1;
  t2 = z - t2;
  long double a2 = t1 + t2;
  /* Ensure the arithmetic is not scheduled after feclearexcept call.  */
  math_force_eval (m2);
  math_force_eval (a2);
  feclearexcept (FE_INEXACT);

  /* If the result is an exact zero, ensure it has the correct sign.  */
  if (a1 == 0 && m2 == 0)
    {
      feupdateenv (&env);
      /* Ensure that round-to-nearest value of z + m1 is not reused.  */
      z = math_opt_barrier (z);
      return z + m1;
    }

  fesetround (FE_TOWARDZERO);
  /* Perform m2 + a2 addition with round to odd.  */
  u.d = a2 + m2;

  if (__glibc_likely (adjust == 0))
    {
      if ((u.ieee.mantissa1 & 1) == 0 && u.ieee.exponent != 0x7fff)
	u.ieee.mantissa1 |= fetestexcept (FE_INEXACT) != 0;
      feupdateenv (&env);
      /* Result is a1 + u.d.  */
      return a1 + u.d;
    }
  else if (__glibc_likely (adjust > 0))
    {
      if ((u.ieee.mantissa1 & 1) == 0 && u.ieee.exponent != 0x7fff)
	u.ieee.mantissa1 |= fetestexcept (FE_INEXACT) != 0;
      feupdateenv (&env);
      /* Result is a1 + u.d, scaled up.  */
      return (a1 + u.d) * 0x1p64L;
    }
  else
    {
      if ((u.ieee.mantissa1 & 1) == 0)
	u.ieee.mantissa1 |= fetestexcept (FE_INEXACT) != 0;
      v.d = a1 + u.d;
      /* Ensure the addition is not scheduled after fetestexcept call.  */
      math_force_eval (v.d);
      int j = fetestexcept (FE_INEXACT) != 0;
      feupdateenv (&env);
      /* Ensure the following computations are performed in default rounding
	 mode instead of just reusing the round to zero computation.  */
      asm volatile ("" : "=m" (u) : "m" (u));
      /* If a1 + u.d is exact, the only rounding happens during
	 scaling down.  */
      if (j == 0)
	return v.d * 0x1p-130L;
      /* If result rounded to zero is not subnormal, no double
	 rounding will occur.  */
      if (v.ieee.exponent > 130)
	return (a1 + u.d) * 0x1p-130L;
      /* If v.d * 0x1p-130L with round to zero is a subnormal above
	 or equal to LDBL_MIN / 2, then v.d * 0x1p-130L shifts mantissa
	 down just by 1 bit, which means v.ieee.mantissa1 |= j would
	 change the round bit, not sticky or guard bit.
	 v.d * 0x1p-130L never normalizes by shifting up,
	 so round bit plus sticky bit should be already enough
	 for proper rounding.  */
      if (v.ieee.exponent == 130)
	{
	  /* If the exponent would be in the normal range when
	     rounding to normal precision with unbounded exponent
	     range, the exact result is known and spurious underflows
	     must be avoided on systems detecting tininess after
	     rounding.  */
	  if (TININESS_AFTER_ROUNDING)
	    {
	      w.d = a1 + u.d;
	      if (w.ieee.exponent == 131)
		return w.d * 0x1p-130L;
	    }
	  /* v.ieee.mantissa1 & 2 is LSB bit of the result before rounding,
	     v.ieee.mantissa1 & 1 is the round bit and j is our sticky
	     bit.  */
	  w.d = 0.0L;
	  w.ieee.mantissa1 = ((v.ieee.mantissa1 & 3) << 1) | j;
	  w.ieee.negative = v.ieee.negative;
	  v.ieee.mantissa1 &= ~3U;
	  v.d *= 0x1p-130L;
	  w.d *= 0x1p-2L;
	  return v.d + w.d;
	}
      v.ieee.mantissa1 |= j;
      return v.d * 0x1p-130L;
    }
}
libm_alias_ldouble (__fma, fma)
