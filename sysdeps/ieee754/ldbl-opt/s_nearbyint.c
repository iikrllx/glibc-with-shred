#include <math_ldbl_opt.h>
#include <sysdeps/ieee754/dbl-64/s_nearbyint.c>
#if LONG_DOUBLE_COMPAT(libm, GLIBC_2_1)
compat_symbol (libm, __nearbyint, nearbyintl, GLIBC_2_1);
#endif
