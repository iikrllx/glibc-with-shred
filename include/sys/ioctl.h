#ifndef _SYS_IOCTL_H
#include <misc/sys/ioctl.h>

/* Now define the internal interfaces.  */
extern int __ioctl __P ((int __fd, unsigned long int __request, ...));
#endif
