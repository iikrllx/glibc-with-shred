/* Multiple versions of __mempcpy_chk
   All versions must be listed in ifunc-impl-list.c.
   Copyright (C) 2017-2023 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

/* Define multiple versions only for the definition in libc.so. */
#if IS_IN (libc) && defined SHARED
# define __mempcpy_chk __redirect_mempcpy_chk
# include <string.h>
# undef __mempcpy_chk

# define SYMBOL_NAME mempcpy_chk
# include "ifunc-memmove.h"

libc_ifunc_redirected (__redirect_mempcpy_chk, __mempcpy_chk,
		       IFUNC_SELECTOR ());
# ifdef SHARED
__hidden_ver1 (__mempcpy_chk, __GI___mempcpy_chk, __redirect_mempcpy_chk)
  __attribute__ ((visibility ("hidden"))) __attribute_copy__ (__mempcpy_chk);
# endif
#else
# include <debug/mempcpy_chk.c>
#endif
