#ifndef _SYS_TIMES_H
#include <posix/sys/times.h>

/* Now define the internal interfaces.  */
extern clock_t __times (struct tms *__buffer) __THROW;
#endif
