/* ARM is (usually) little-endian but with a big-endian FPU.  */

#ifndef _ENDIAN_H
# error "Never use <bits/endian.h> directly; include <endian.h> instead."
#endif

#define __BYTE_ORDER __LITTLE_ENDIAN
#define __FLOAT_WORD_ORDER __BIG_ENDIAN
