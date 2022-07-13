/* Multiple versions of strcmp.
   All versions must be listed in ifunc-impl-list.c.
   Copyright (C) 2017-2022 Free Software Foundation, Inc.
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

/* Define multiple versions only for the definition in libc.  */
#if IS_IN (libc)
# define strcmp __redirect_strcmp
# include <string.h>
# undef strcmp

# define SYMBOL_NAME strcmp
# include <init-arch.h>

extern __typeof (REDIRECT_NAME) OPTIMIZE (evex) attribute_hidden;

extern __typeof (REDIRECT_NAME) OPTIMIZE (avx2) attribute_hidden;
extern __typeof (REDIRECT_NAME) OPTIMIZE (avx2_rtm) attribute_hidden;

extern __typeof (REDIRECT_NAME) OPTIMIZE (sse42) attribute_hidden;

extern __typeof (REDIRECT_NAME)
    OPTIMIZE (sse2_unaligned) attribute_hidden;
extern __typeof (REDIRECT_NAME) OPTIMIZE (sse2) attribute_hidden;



static inline void *
IFUNC_SELECTOR (void)
{
  const struct cpu_features *cpu_features = __get_cpu_features ();

  if (X86_ISA_CPU_FEATURE_USABLE_P (cpu_features, AVX2)
      && X86_ISA_CPU_FEATURES_ARCH_P (cpu_features,
				      AVX_Fast_Unaligned_Load, ))
    {
      if (X86_ISA_CPU_FEATURE_USABLE_P (cpu_features, AVX512VL)
	  && X86_ISA_CPU_FEATURE_USABLE_P (cpu_features, AVX512BW)
	  && X86_ISA_CPU_FEATURE_USABLE_P (cpu_features, BMI2))
	return OPTIMIZE (evex);

      if (CPU_FEATURE_USABLE_P (cpu_features, RTM))
	return OPTIMIZE (avx2_rtm);

      if (X86_ISA_CPU_FEATURES_ARCH_P (cpu_features,
				       Prefer_No_VZEROUPPER, !))
	return OPTIMIZE (avx2);
    }

  if (X86_ISA_CPU_FEATURE_USABLE_P (cpu_features, SSE4_2)
      /* Keep this as runtime check.  Some ISA level >= 2 CPUs such as
	 Tremont, Silvermont, and more check this.  */
      && !CPU_FEATURES_ARCH_P (cpu_features, Slow_SSE4_2))
    return OPTIMIZE (sse42);

  /* Keep this as runtime check.  The standard SSE2 version has
     meaningful optimizations around keeping all loads aligned in the
     main loop which can benefit some ISA level >= 2 CPUs.  */
  if (CPU_FEATURES_ARCH_P (cpu_features, Fast_Unaligned_Load))
    return OPTIMIZE (sse2_unaligned);

  return OPTIMIZE (sse2);
}

libc_ifunc_redirected (__redirect_strcmp, strcmp, IFUNC_SELECTOR ());

# ifdef SHARED
__hidden_ver1 (strcmp, __GI_strcmp, __redirect_strcmp)
  __attribute__ ((visibility ("hidden"))) __attribute_copy__ (strcmp);
# endif
#endif
