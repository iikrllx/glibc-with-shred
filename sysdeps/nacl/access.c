/* Check file access permission.  NaCl version.
   Copyright (C) 2015-2017 Free Software Foundation, Inc.
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

#include <unistd.h>
#include <nacl-interfaces.h>

/* Test for access to FILE without setting errno.  */
int
__access_noerrno (const char *file, int type)
{
  return NACL_CALL_NOERRNO (__nacl_irt_dev_filename.access (file, type), 0);
}

/* Test for access to FILE.  */
int
__access (const char *file, int type)
{
  return NACL_CALL (__nacl_irt_dev_filename.access (file, type), 0);
}
weak_alias (__access, access)
