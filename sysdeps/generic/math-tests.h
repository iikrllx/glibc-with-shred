/* Configuration for math tests.  Generic version.
   Copyright (C) 2013-2018 Free Software Foundation, Inc.
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

#include <bits/floatn.h>

/* Expand the appropriate macro for whether to enable tests for a
   given type.  */
#if __HAVE_DISTINCT_FLOAT128
# define MATH_TESTS_TG(PREFIX, ARGS, TYPE)				\
  (sizeof (TYPE) == sizeof (float) ? PREFIX ## float ARGS		\
   : sizeof (TYPE) == sizeof (double) ? PREFIX ## double ARGS		\
   : __builtin_types_compatible_p (TYPE, _Float128) ? PREFIX ## float128 ARGS \
   : PREFIX ## long_double ARGS)
# else
# define MATH_TESTS_TG(PREFIX, ARGS, TYPE)				\
  (sizeof (TYPE) == sizeof (float) ? PREFIX ## float ARGS		\
   : sizeof (TYPE) == sizeof (double) ? PREFIX ## double ARGS		\
   : PREFIX ## long_double ARGS)
#endif

/* Return nonzero value if to run tests involving sNaN values for X.  */
#define SNAN_TESTS(x) MATH_TESTS_TG (SNAN_TESTS_, , x)

#define ROUNDING_TESTS(TYPE, MODE)		\
  MATH_TESTS_TG (ROUNDING_TESTS_, (MODE), TYPE)

#define EXCEPTION_TESTS(TYPE) MATH_TESTS_TG (EXCEPTION_TESTS_, , TYPE)

/* Indicate whether the given exception trap(s) can be enabled
   in feenableexcept.  If non-zero, the traps are always supported.
   If zero, traps may or may not be supported depending on the
   target (this can be determined by checking the return value
   of feenableexcept).  This enables skipping of tests which use
   traps.  By default traps are supported unless overridden.  */
#ifndef EXCEPTION_ENABLE_SUPPORTED
# define EXCEPTION_ENABLE_SUPPORTED(EXCEPT)			\
   (EXCEPTION_TESTS_float || EXCEPTION_TESTS_double)
#endif

/* Indicate whether exception traps, if enabled, occur whenever an
   exception flag is set explicitly, so it is not possible to set flag
   bits with traps enabled without causing traps to be taken.  If
   traps cannot be enabled, the value of this macro does not
   matter.  */
#ifndef EXCEPTION_SET_FORCES_TRAP
# define EXCEPTION_SET_FORCES_TRAP 0
#endif

#include <math-tests-exceptions.h>
#include <math-tests-rounding.h>
#include <math-tests-snan.h>
#include <math-tests-snan-cast.h>
#include <math-tests-snan-payload.h>
