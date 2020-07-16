#ifndef _SYS_STAT_H
#include <io/sys/stat.h>

#ifndef _ISOMAC
# include <xstatver.h>

/* Now define the internal interfaces. */
extern int __stat (const char *__file, struct stat *__buf);
extern int __stat64 (const char *__file, struct stat64 *__buf);
extern int __fstat (int __fd, struct stat *__buf);
extern int __fstat64 (int __fd, struct stat64 *__buf);
extern int __lstat (const char *__file, struct stat *__buf);
extern int __lstat64 (const char *__file, struct stat64 *__buf);
extern int __fstatat (int dirfd, const char *pathname, struct stat *buf,
		      int flags);
extern int __fstatat64 (int dirfd, const char *pathname, struct stat64 *buf,
			int flags);
# if IS_IN (libc) || (IS_IN (rtld) && !defined NO_RTLD_HIDDEN)
hidden_proto (__stat64)
hidden_proto (__fstat64)
hidden_proto (__lstat64)
hidden_proto (__fstatat64)
# endif

extern int __chmod (const char *__file, __mode_t __mode);
libc_hidden_proto (__chmod)
extern int __fchmod (int __fd, __mode_t __mode);
libc_hidden_proto (fchmodat)
extern __mode_t __umask (__mode_t __mask);
extern int __mkdir (const char *__path, __mode_t __mode);
libc_hidden_proto (__mkdir)

extern int __mknodat (int fd, const char *path, mode_t mode, dev_t dev);
libc_hidden_proto (__mknodat);
extern int __mknod (const char *__path,
		    __mode_t __mode, __dev_t __dev);
libc_hidden_proto (__mknod);

extern int __xmknod (int __ver, const char *__path, __mode_t __mode,
		     __dev_t *__dev);
libc_hidden_proto (__xmknod)
extern int __xmknodat (int __ver, int __fd, const char *__path,
		       __mode_t __mode, __dev_t *__dev);
libc_hidden_proto (__xmknodat)

int __fxstat (int __ver, int __fildes, struct stat *__stat_buf);
int __xstat (int __ver, const char *__filename,
	     struct stat *__stat_buf);
int __lxstat (int __ver, const char *__filename, struct stat *__stat_buf);
int __fxstatat (int __ver, int __fildes, const char *__filename,
		struct stat *__stat_buf, int __flag);
int __fxstat64 (int ver, int __fildes, struct stat64 *__stat_buf);
int __xstat64 (int ver, const char *__filename, struct stat64 *__stat_buf);
int __lxstat64 (int ver, const char *__filename, struct stat64 *__stat_buf);
int __fxstatat64 (int ver, int __fildes, const char *__filename,
		  struct stat64 *__stat_buf, int __flag);
libc_hidden_proto (__fxstat);
libc_hidden_proto (__xstat);
libc_hidden_proto (__lxstat);
libc_hidden_proto (__fxstatat);
# if IS_IN (libc) || (IS_IN (rtld) && !defined NO_RTLD_HIDDEN)
hidden_proto (__fxstat64);
hidden_proto (__xstat64);
hidden_proto (__lxstat64);
hidden_proto (__fxstatat64);
# endif

# ifdef NO_RTLD_HIDDEN
/* These are still required for Hurd.  */
#  define stat(fname, buf) __xstat (_STAT_VER, fname, buf)
#  define lstat(fname, buf)  __lxstat (_STAT_VER, fname, buf)
#  define __lstat(fname, buf)  __lxstat (_STAT_VER, fname, buf)
#  define lstat64(fname, buf)  __lxstat64 (_STAT_VER, fname, buf)
#  define __lstat64(fname, buf)  __lxstat64 (_STAT_VER, fname, buf)
#  define stat64(fname, buf) __xstat64 (_STAT_VER, fname, buf)
#  define __stat64(fname, buf) __xstat64 (_STAT_VER, fname, buf)
#  define fstat64(fd, buf) __fxstat64 (_STAT_VER, fd, buf)
#  define __fstat64(fd, buf) __fxstat64 (_STAT_VER, fd, buf)
#  define fstat(fd, buf) __fxstat (_STAT_VER, fd, buf)
#  define __fstat(fd, buf) __fxstat (_STAT_VER, fd, buf)
#  define __fstatat(dfd, fname, buf, flag) \
    __fxstatat (_STAT_VER, dfd, fname, buf, flag)
#  define __fstatat64(dfd, fname, buf, flag) \
    __fxstatat64 (_STAT_VER, dfd, fname, buf, flag)
# endif /* NO_RTLD_HIDDEN  */

#endif
#endif
