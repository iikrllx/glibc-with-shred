/* Multiple versions of copysignf.
   Copyright (C) 2013-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <math.h>
#include <shlib-compat.h>
#include "init-arch.h"

/* It's safe to use double-precision implementation for single-precision. */
extern __typeof (__copysignf) __copysign_ppc64 attribute_hidden;
extern __typeof (__copysignf) __copysign_power6 attribute_hidden;

libc_ifunc (__copysignf,
	    (hwcap & PPC_FEATURE_ARCH_2_05)
	    ? __copysign_power6
            : __copysign_ppc64);

weak_alias (__copysignf, copysignf)
