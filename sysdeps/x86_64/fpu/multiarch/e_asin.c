#if defined HAVE_FMA4_SUPPORT || defined HAVE_AVX_SUPPORT
# include <init-arch.h>
# include <math_private.h>

extern double __ieee754_acos_sse2 (double);
extern double __ieee754_asin_sse2 (double);
extern double __ieee754_acos_avx (double);
extern double __ieee754_asin_avx (double);
# ifdef HAVE_FMA4_SUPPORT
extern double __ieee754_acos_fma4 (double);
extern double __ieee754_asin_fma4 (double);
# else
#  undef HAS_FMA4
#  define HAS_FMA4 0
#  define __ieee754_acos_fma4 ((void *) 0)
#  define __ieee754_asin_fma4 ((void *) 0)
# endif

libm_ifunc (__ieee754_acos,
	    HAS_FMA4 ? __ieee754_acos_fma4
	    : (HAS_AVX ? __ieee754_acos_avx : __ieee754_acos_sse2));
strong_alias (__ieee754_acos, __acos_finite)

libm_ifunc (__ieee754_asin,
	    HAS_FMA4 ? __ieee754_asin_fma4
	    : (HAS_AVX ? __ieee754_asin_avx : __ieee754_asin_sse2));
strong_alias (__ieee754_asin, __asin_finite)

# define __ieee754_acos __ieee754_acos_sse2
# define __ieee754_asin __ieee754_asin_sse2
#endif


#include <sysdeps/ieee754/dbl-64/e_asin.c>
