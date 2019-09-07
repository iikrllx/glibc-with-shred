/* Multiple versions of wmemchr.
   Copyright (C) 2015-2019 Free Software Foundation, Inc.
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

#include <ifunc-wmemchr.h>

#if HAVE_WMEMCHR_IFUNC
# define wmemchr __redirect_wmemchr
# define __wmemchr __redirect___wmemchr
# include <wchar.h>
# undef wmemchr
# undef __wmemchr
# include <ifunc-resolve.h>

# if HAVE_WMEMCHR_C
extern __typeof (__redirect___wmemchr) WMEMCHR_C attribute_hidden;
# endif

# if HAVE_WMEMCHR_Z13
extern __typeof (__redirect___wmemchr) WMEMCHR_Z13 attribute_hidden;
# endif

s390_libc_ifunc_expr (__redirect___wmemchr, __wmemchr,
		      (HAVE_WMEMCHR_Z13 && (hwcap & HWCAP_S390_VX))
		      ? WMEMCHR_Z13
		      : WMEMCHR_DEFAULT
		      )
weak_alias (__wmemchr, wmemchr)
#endif
