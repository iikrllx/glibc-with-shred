#if __GNUC_PREREQ (13, 0)
# define USE_LLRINT_BUILTIN 1
# define USE_LLRINTF_BUILTIN 1
#else
# define USE_LLRINT_BUILTIN 0
# define USE_LLRINTF_BUILTIN 0
#endif

#define USE_LLRINTL_BUILTIN 0
#define USE_LLRINTF128_BUILTIN 0
