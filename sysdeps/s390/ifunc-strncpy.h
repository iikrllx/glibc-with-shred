/* strncpy variant information on S/390 version.
   Copyright (C) 2018-2019 Free Software Foundation, Inc.
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

#if defined USE_MULTIARCH && IS_IN (libc)		\
  && ! defined HAVE_S390_MIN_Z13_ZARCH_ASM_SUPPORT
# define HAVE_STRNCPY_IFUNC	1
#else
# define HAVE_STRNCPY_IFUNC	0
#endif

#ifdef HAVE_S390_VX_ASM_SUPPORT
# define HAVE_STRNCPY_IFUNC_AND_VX_SUPPORT HAVE_STRNCPY_IFUNC
#else
# define HAVE_STRNCPY_IFUNC_AND_VX_SUPPORT 0
#endif

#if defined HAVE_S390_MIN_Z13_ZARCH_ASM_SUPPORT
# define STRNCPY_DEFAULT	STRNCPY_Z13
# define HAVE_STRNCPY_Z900_G5	0
# define HAVE_STRNCPY_Z13	1
#else
# define STRNCPY_DEFAULT	STRNCPY_Z900_G5
# define HAVE_STRNCPY_Z900_G5	1
# define HAVE_STRNCPY_Z13	HAVE_STRNCPY_IFUNC_AND_VX_SUPPORT
#endif

#if HAVE_STRNCPY_Z900_G5
# define STRNCPY_Z900_G5	__strncpy_default
#else
# define STRNCPY_Z900_G5	NULL
#endif

#if HAVE_STRNCPY_Z13
# define STRNCPY_Z13		__strncpy_vx
#else
# define STRNCPY_Z13		NULL
#endif
