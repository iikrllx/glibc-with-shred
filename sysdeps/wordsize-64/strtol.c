/* We have to irritate the compiler a bit.  */
#define __strtoll_internal __strtoll_internal_XXX
#define strtoll strtoll_XXX

#include <sysdeps/generic/strtol.c>

#undef __strtoll_internal
#undef strtoll
strong_alias (__strtol_internal, __strtoll_internal)
weak_alias (__strtoll_internal, strtoll)
