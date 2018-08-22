/* Definitions for float vector tests with vector length 16.
   Copyright (C) 2014-2018 Free Software Foundation, Inc.
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

#include "test-float.h"
#include "test-math-no-inline.h"
#include "test-math-vector.h"
#include <math-tests-rounding.h>

#undef ROUNDING_TESTS_float
#define ROUNDING_TESTS_float(MODE) ((MODE) == FE_TONEAREST)

#define VEC_SUFF _vlen16
#define VEC_LEN 16
