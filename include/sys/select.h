#include <misc/sys/select.h>

/* Now define the internal interfaces.  */
extern int __pselect __P ((int __nfds, __fd_set *__readfds,
			   __fd_set *__writefds, __fd_set *__exceptfds,
			   struct timespec *__timeout));
