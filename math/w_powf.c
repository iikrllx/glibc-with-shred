#include <math-type-macros-float.h>
#undef __USE_WRAPPER_TEMPLATE
#define __USE_WRAPPER_TEMPLATE 1
#undef declare_mgen_alias
#define declare_mgen_alias(a, b)
#include <w_pow_template.c>
versioned_symbol (libm, __powf, powf, GLIBC_2_27);
