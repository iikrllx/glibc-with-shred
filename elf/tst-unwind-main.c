/* Test unwinding through main.
   Copyright (C) 2018 Free Software Foundation, Inc.
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

#include <unwind.h>
#include <unistd.h>
#include <support/test-driver.h>

static _Unwind_Reason_Code
callback (struct _Unwind_Context *ctx, void *arg)
{
  return _URC_NO_REASON;
}

int
main (void)
{
  /* Arrange for this test to be killed if _Unwind_Backtrace runs into an
     endless loop.  We cannot use the test driver because the complete
     call chain needs to be compiled with -funwind-tables so that
     _Unwind_Backtrace is able to reach _start.  */
  alarm (DEFAULT_TIMEOUT);
  _Unwind_Backtrace (callback, 0);
}
