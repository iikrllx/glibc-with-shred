/* Default strlen implementation for S/390.
   Copyright (C) 2015-2021 Free Software Foundation, Inc.
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

#include <ifunc-strlen.h>

#if HAVE_STRLEN_C
# if HAVE_STRLEN_IFUNC
#  define STRLEN STRLEN_C
#  if defined SHARED && IS_IN (libc)
#   undef libc_hidden_builtin_def
#   define libc_hidden_builtin_def(name)		\
  __hidden_ver1 (__strlen_c, __GI_strlen, __strlen_c);
#  endif
# endif

# include <string/strlen.c>
#endif
