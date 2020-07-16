/* Versions of the 'struct stat' data structure used in compatibility xstat
   functions.  */
#define _STAT_VER_LINUX_OLD	1
#define _STAT_VER_KERNEL	1
#define _STAT_VER_SVR4		2
#define _STAT_VER_LINUX	  3
#if __WORDSIZE == 32
# define _STAT_VER		_STAT_VER_LINUX
#else
# define _STAT_VER		_STAT_VER_KERNEL
#endif

/* Versions of the 'xmknod' interface used in compatibility xmknod
   functions.  */
#define _MKNOD_VER_LINUX	1
#define _MKNOD_VER_SVR4		2
#define _MKNOD_VER		_MKNOD_VER_LINUX
