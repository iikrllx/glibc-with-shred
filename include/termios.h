#ifndef _TERMIOS_H
#include <termios/termios.h>

/* Now define the internal interfaces.  */
extern int __tcgetattr (int __fd, struct termios *__termios_p) __THROW;
#endif
