/* We must use the syscall directly since __ioctl does some extra work.  */

#include <sys/ioctl.h>

#include <sysdep.h>
#include <bp-checks.h>

struct __kernel_termios;

static inline int
tcgetattr_ioctl (int fd, unsigned long int request,
		 struct __kernel_termios *termios_p)
{
  return INLINE_SYSCALL (ioctl, 3, fd, request, CHECK_1 (termios_p));
}

#define __ioctl tcgetattr_ioctl

#include <sysdeps/unix/sysv/linux/tcgetattr.c>
