#include <math_ldbl_opt.h>
#include <math/w_exp_compat.c>
#if LONG_DOUBLE_COMPAT(libm, GLIBC_2_0)
compat_symbol (libm, __exp, expl, GLIBC_2_0);
#endif
