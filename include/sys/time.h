#ifndef _SYS_TIME_H
#include <time/sys/time.h>

/* Now document the internal interfaces.  */
extern int __gettimeofday (struct timeval *__tv,
			   struct timezone *__tz) __THROW;
extern int __settimeofday (__const struct timeval *__tv,
			   __const struct timezone *__tz) __THROW;
extern int __adjtime (__const struct timeval *__delta,
		      struct timeval *__olddelta) __THROW;
extern int __getitimer (enum __itimer_which __which,
			struct itimerval *__value) __THROW;
extern int __setitimer (enum __itimer_which __which,
			__const struct itimerval *__new,
			struct itimerval *__old) __THROW;
extern int __utimes (__const char *__file, struct timeval __tvp[2]) __THROW;
#endif
