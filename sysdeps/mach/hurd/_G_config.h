/* This file is needed by libio to define various configuration parameters.
   These are always the same in the GNU C library.  */

#ifndef _G_config_h
#define _G_config_h 1

/* Define types for libio in terms of the standard internal type names.  */

#include <bits/types.h>
#define __need_size_t
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
# define __need_wchar_t
#endif
#define __need_NULL
#include <stddef.h>
#define __need_mbstate_t
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
# define __need_wint_t
#endif
#include <wchar.h>
#define _G_size_t	size_t
typedef struct
{
  __off_t __pos;
  __mbstate_t __state;
} _G_fpos_t;
typedef struct
{
  __off64_t __pos;
  __mbstate_t __state;
} _G_fpos64_t;
#define _G_ssize_t	__ssize_t
#define _G_off_t	__off_t
#define _G_off64_t	__off64_t
#define	_G_pid_t	__pid_t
#define	_G_uid_t	__uid_t
#define _G_wchar_t	wchar_t
#define _G_wint_t	wint_t
#define _G_stat64	stat64
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
# include <gconv.h>
typedef union
{
  struct __gconv_info __cd;
  struct
  {
    struct __gconv_info __cd;
    struct __gconv_step_data __data;
  } __combined;
} _G_iconv_t;
#endif


/* These library features are always available in the GNU C library.  */
#define _G_HAVE_SYS_WAIT 1
#define _G_NEED_STDARG_H 1
#define _G_va_list __gnuc_va_list

#define _G_HAVE_MMAP 1

#define _G_IO_IO_FILE_VERSION 0x20001

#define _G_OPEN64	__open64
#define _G_LSEEK64	__lseek64
#define _G_MMAP64	__mmap64
#define _G_FSTAT64(fd,buf) __fxstat64 (_STAT_VER, fd, buf)

/* This is defined by <bits/stat.h> if `st_blksize' exists.  */
#define _G_HAVE_ST_BLKSIZE defined (_STATBUF_ST_BLKSIZE)

#define _G_BUFSIZ 8192

#endif	/* _G_config.h */
