/* Implementation of the TEST_VERIFY and TEST_VERIFY_EXIT macros.
   Copyright (C) 2016-2017 Free Software Foundation, Inc.
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

#include <support/check.h>

#include <stdio.h>
#include <stdlib.h>

void
support_test_verify_impl (const char *file, int line, const char *expr)
{
  support_record_failure ();
  printf ("error: %s:%d: not true: %s\n", file, line, expr);
}

void
support_test_verify_exit_impl (int status, const char *file, int line,
                               const char *expr)
{
  support_test_verify_impl (file, line, expr);
  exit (status);
}
