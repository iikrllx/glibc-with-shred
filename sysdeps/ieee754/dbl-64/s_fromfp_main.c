/* Round to integer type.  dbl-64 version.
   Copyright (C) 2016-2023 Free Software Foundation, Inc.
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

#include <errno.h>
#include <fenv.h>
#include <math.h>
#include <math_private.h>
#include <libm-alias-double.h>
#include <stdbool.h>
#include <stdint.h>

#define BIAS 0x3ff
#define MANT_DIG 53

#if UNSIGNED
# define RET_TYPE uintmax_t
#else
# define RET_TYPE intmax_t
#endif

#include <fromfp.h>

RET_TYPE
FUNC (double x, int round, unsigned int width)
{
  if (width > INTMAX_WIDTH)
    width = INTMAX_WIDTH;
  uint64_t ix;
  EXTRACT_WORDS64 (ix, x);
  bool negative = (ix & 0x8000000000000000ULL) != 0;
  if (width == 0)
    return fromfp_domain_error (negative, width);
  ix &= 0x7fffffffffffffffULL;
  if (ix == 0)
    return 0;
  int exponent = ix >> (MANT_DIG - 1);
  exponent -= BIAS;
  int max_exponent = fromfp_max_exponent (negative, width);
  if (exponent > max_exponent)
    return fromfp_domain_error (negative, width);

  ix &= ((1ULL << (MANT_DIG - 1)) - 1);
  ix |= 1ULL << (MANT_DIG - 1);
  uintmax_t uret;
  bool half_bit, more_bits;
  if (exponent >= MANT_DIG - 1)
    {
      uret = ix;
      uret <<= exponent - (MANT_DIG - 1);
      half_bit = false;
      more_bits = false;
    }
  else if (exponent >= -1)
    {
      uint64_t h = 1ULL << (MANT_DIG - 2 - exponent);
      half_bit = (ix & h) != 0;
      more_bits = (ix & (h - 1)) != 0;
      uret = ix >> (MANT_DIG - 1 - exponent);
    }
  else
    {
      uret = 0;
      half_bit = false;
      more_bits = true;
    }
  return fromfp_round_and_return (negative, uret, half_bit, more_bits, round,
				  exponent, max_exponent, width);
}
