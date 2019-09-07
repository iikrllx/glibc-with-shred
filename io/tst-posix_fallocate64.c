/* Basic posix_fallocate tests (with _FILE_OFFSET_BITS).
   Copyright (C) 2016-2019 Free Software Foundation, Inc.
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

#define _FILE_OFFSET_BITS 64
#include "tst-posix_fallocate-common.c"

static int
do_test (void)
{
  struct stat st;
  int ret;

  if (fstat (temp_fd, &st) != 0)
    FAIL_EXIT1 ("1st fstat failed");

  if (st.st_size != 0)
    FAIL_EXIT1 ("file not created with size 0");

  ret = do_test_with_offset (512);
  if (ret == 1)
    return 1;

  off_t base_offset = UINT32_MAX + 512LL;
  ret = do_test_with_offset (base_offset);
  if (ret == 1)
    return 1;

  return 0;
}
