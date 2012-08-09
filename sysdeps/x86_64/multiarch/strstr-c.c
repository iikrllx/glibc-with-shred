#include "init-arch.h"

#define STRSTR __strstr_sse2
#ifdef SHARED
# undef libc_hidden_builtin_def
# define libc_hidden_builtin_def(name) \
  __hidden_ver1 (__strstr_sse2, __GI_strstr, __strstr_sse2);
#endif

/* Redefine strstr so that the compiler won't complain about the type
   mismatch with the IFUNC selector in strong_alias, below.  */
#undef strstr
#define strstr __redirect_strstr

#include "string/strstr.c"

extern __typeof (__redirect_strstr) __strstr_sse42 attribute_hidden;
extern __typeof (__redirect_strstr) __strstr_sse2 attribute_hidden;

/* Avoid DWARF definition DIE on ifunc symbol so that GDB can handle
   ifunc symbol properly.  */
extern __typeof (__redirect_strstr) __libc_strstr;
libc_ifunc (__libc_strstr, HAS_SSE4_2 ? __strstr_sse42 : __strstr_sse2)

#undef strstr
strong_alias (__libc_strstr, strstr)
