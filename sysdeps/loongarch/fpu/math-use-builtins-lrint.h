#if __GNUC_PREREQ (13, 0)
# define USE_LRINT_BUILTIN 1
# define USE_LRINTF_BUILTIN 1
#else
# define USE_LRINT_BUILTIN 0
# define USE_LRINTF_BUILTIN 0
#endif

#define USE_LRINTL_BUILTIN 0
#define USE_LRINTF128_BUILTIN 0
