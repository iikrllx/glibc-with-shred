#include <math-type-macros-double.h>
#undef __USE_WRAPPER_TEMPLATE
#define __USE_WRAPPER_TEMPLATE 1
#undef declare_mgen_alias
#define declare_mgen_alias(a, b)
#include <w_exp2_template.c>
versioned_symbol (libm, __exp2, exp2, GLIBC_2_29);
libm_alias_double_other (__exp2, exp2)
