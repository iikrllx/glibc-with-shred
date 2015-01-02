/* Copyright (C) 1993-2015 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include "stdio.h"
#include <errno.h>
#include <shlib-compat.h>

int
__new_pclose (fp)
     FILE *fp;
{
#if 0
  /* Does not actually test that stream was created by popen(). Instead,
     it depends on the filebuf::sys_close() virtual to Do The Right Thing. */
  if (fp is not a proc_file)
    return -1;
#endif
  return _IO_new_fclose (fp);
}

versioned_symbol (libc, __new_pclose, pclose, GLIBC_2_1);
