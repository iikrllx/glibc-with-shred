#include <math_ldbl_opt.h>
#include <sysdeps/ieee754/dbl-64/wordsize-64/s_logb.c>
#if LONG_DOUBLE_COMPAT(libm, GLIBC_2_0)
compat_symbol (libm, __logb, logbl, GLIBC_2_0);
#endif
