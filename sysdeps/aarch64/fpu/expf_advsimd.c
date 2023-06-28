/* Single-precision vector (Advanced SIMD) exp function.

   Copyright (C) 2023 Free Software Foundation, Inc.
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

#include "v_math.h"

static const struct data
{
  float32x4_t poly[5];
  float32x4_t shift, inv_ln2, ln2_hi, ln2_lo;
  uint32x4_t exponent_bias;
#if !WANT_SIMD_EXCEPT
  float32x4_t special_bound, scale_thresh;
#endif
} data = {
  /* maxerr: 1.45358 +0.5 ulp.  */
  .poly = { V4 (0x1.0e4020p-7f), V4 (0x1.573e2ep-5f), V4 (0x1.555e66p-3f),
	    V4 (0x1.fffdb6p-2f), V4 (0x1.ffffecp-1f) },
  .shift = V4 (0x1.8p23f),
  .inv_ln2 = V4 (0x1.715476p+0f),
  .ln2_hi = V4 (0x1.62e4p-1f),
  .ln2_lo = V4 (0x1.7f7d1cp-20f),
  .exponent_bias = V4 (0x3f800000),
#if !WANT_SIMD_EXCEPT
  .special_bound = V4 (126.0f),
  .scale_thresh = V4 (192.0f),
#endif
};

#define C(i) d->poly[i]

#if WANT_SIMD_EXCEPT

# define TinyBound v_u32 (0x20000000)	/* asuint (0x1p-63).  */
# define BigBound v_u32 (0x42800000)	/* asuint (0x1p6).  */
# define SpecialBound v_u32 (0x22800000) /* BigBound - TinyBound.  */

static float32x4_t VPCS_ATTR NOINLINE
special_case (float32x4_t x, float32x4_t y, uint32x4_t cmp)
{
  /* If fenv exceptions are to be triggered correctly, fall back to the scalar
     routine to special lanes.  */
  return v_call_f32 (expf, x, y, cmp);
}

#else

# define SpecialOffset v_u32 (0x82000000)
# define SpecialBias v_u32 (0x7f000000)

static float32x4_t VPCS_ATTR NOINLINE
special_case (float32x4_t poly, float32x4_t n, uint32x4_t e, uint32x4_t cmp1,
	      float32x4_t scale, const struct data *d)
{
  /* 2^n may overflow, break it up into s1*s2.  */
  uint32x4_t b = vandq_u32 (vclezq_f32 (n), SpecialOffset);
  float32x4_t s1 = vreinterpretq_f32_u32 (vaddq_u32 (b, SpecialBias));
  float32x4_t s2 = vreinterpretq_f32_u32 (vsubq_u32 (e, b));
  uint32x4_t cmp2 = vcagtq_f32 (n, d->scale_thresh);
  float32x4_t r2 = vmulq_f32 (s1, s1);
  float32x4_t r1 = vmulq_f32 (vfmaq_f32 (s2, poly, s2), s1);
  /* Similar to r1 but avoids double rounding in the subnormal range.  */
  float32x4_t r0 = vfmaq_f32 (scale, poly, scale);
  float32x4_t r = vbslq_f32 (cmp1, r1, r0);
  return vbslq_f32 (cmp2, r2, r);
}

#endif

float32x4_t VPCS_ATTR V_NAME_F1 (exp) (float32x4_t x)
{
  const struct data *d = ptr_barrier (&data);
  float32x4_t n, r, r2, scale, p, q, poly, z;
  uint32x4_t cmp, e;

#if WANT_SIMD_EXCEPT
  /* asuint(x) - TinyBound >= BigBound - TinyBound.  */
  cmp = vcgeq_u32 (
      vsubq_u32 (vandq_u32 (vreinterpretq_u32_f32 (x), v_u32 (0x7fffffff)),
		 TinyBound),
      SpecialBound);
  float32x4_t xm = x;
  /* If any lanes are special, mask them with 1 and retain a copy of x to allow
     special case handler to fix special lanes later. This is only necessary if
     fenv exceptions are to be triggered correctly.  */
  if (__glibc_unlikely (v_any_u32 (cmp)))
    x = vbslq_f32 (cmp, v_f32 (1), x);
#endif

  /* exp(x) = 2^n (1 + poly(r)), with 1 + poly(r) in [1/sqrt(2),sqrt(2)]
     x = ln2*n + r, with r in [-ln2/2, ln2/2].  */
  z = vfmaq_f32 (d->shift, x, d->inv_ln2);
  n = vsubq_f32 (z, d->shift);
  r = vfmsq_f32 (x, n, d->ln2_hi);
  r = vfmsq_f32 (r, n, d->ln2_lo);
  e = vshlq_n_u32 (vreinterpretq_u32_f32 (z), 23);
  scale = vreinterpretq_f32_u32 (vaddq_u32 (e, d->exponent_bias));

#if !WANT_SIMD_EXCEPT
  cmp = vcagtq_f32 (n, d->special_bound);
#endif

  r2 = vmulq_f32 (r, r);
  p = vfmaq_f32 (C (1), C (0), r);
  q = vfmaq_f32 (C (3), C (2), r);
  q = vfmaq_f32 (q, p, r2);
  p = vmulq_f32 (C (4), r);
  poly = vfmaq_f32 (p, q, r2);

  if (__glibc_unlikely (v_any_u32 (cmp)))
#if WANT_SIMD_EXCEPT
    return special_case (xm, vfmaq_f32 (scale, poly, scale), cmp);
#else
    return special_case (poly, n, e, cmp, scale, d);
#endif

  return vfmaq_f32 (scale, poly, scale);
}
