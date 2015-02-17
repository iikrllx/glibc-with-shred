/* The MIPS architecture has selectable endianness.
   This file is for a machine using big-endian mode.  */

#ifndef _ENDIAN_H
# error "Never use <bits/endian.h> directly; include <endian.h> instead."
#endif

#ifdef __MIPSEB
# define __BYTE_ORDER __BIG_ENDIAN
#endif
#ifdef __MIPSEL
# define __BYTE_ORDER __LITTLE_ENDIAN
#endif
