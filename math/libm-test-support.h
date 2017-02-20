/* Support code for testing libm functions (common declarations).
   Copyright (C) 1997-2017 Free Software Foundation, Inc.
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

#ifndef LIBM_TEST_SUPPORT_H
#define LIBM_TEST_SUPPORT_H 1

#include <complex.h>
#include <math.h>
#include <float.h>
#include <fenv.h>
#include <limits.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <tininess.h>
#include <math-tests.h>
#include <nan-high-order-bit.h>

extern const int flag_test_errno;
extern const int flag_test_exceptions;
extern const int flag_test_finite;
extern const int flag_test_inline;
extern const int flag_test_mathvec;
extern const char test_msg[];
extern const char qtype_str[];
extern const char doc[];

/* Possible exceptions */
#define NO_EXCEPTION			0x0
#define INVALID_EXCEPTION		0x1
#define DIVIDE_BY_ZERO_EXCEPTION	0x2
#define OVERFLOW_EXCEPTION		0x4
#define UNDERFLOW_EXCEPTION		0x8
#define INEXACT_EXCEPTION		0x10
/* The next flags signals that those exceptions are allowed but not required.   */
#define INVALID_EXCEPTION_OK		0x20
#define DIVIDE_BY_ZERO_EXCEPTION_OK	0x40
#define OVERFLOW_EXCEPTION_OK		0x80
#define UNDERFLOW_EXCEPTION_OK		0x100
/* For "inexact" exceptions, the default is allowed but not required
   unless INEXACT_EXCEPTION or NO_INEXACT_EXCEPTION is specified.  */
#define NO_INEXACT_EXCEPTION		0x200
/* Some special test flags, passed together with exceptions.  */
#define IGNORE_ZERO_INF_SIGN		0x400
#define TEST_NAN_SIGN			0x800
#define TEST_NAN_PAYLOAD		0x1000
#define NO_TEST_INLINE			0x2000
#define XFAIL_TEST			0x4000
/* Indicate errno settings required or disallowed.  */
#define ERRNO_UNCHANGED			0x8000
#define ERRNO_EDOM			0x10000
#define ERRNO_ERANGE			0x20000
/* Flags generated by gen-libm-test.pl, not entered here manually.  */
#define IGNORE_RESULT			0x40000
#define NON_FINITE			0x80000
#define TEST_SNAN			0x100000
#define NO_TEST_MATHVEC			0x200000

#define __CONCATX(a,b) __CONCAT(a,b)

#define TYPE_MIN __CONCATX (PREFIX, _MIN)
#define TYPE_TRUE_MIN __CONCATX (PREFIX, _TRUE_MIN)
#define TYPE_MAX __CONCATX (PREFIX, _MAX)
#define MIN_EXP __CONCATX (PREFIX, _MIN_EXP)
#define MAX_EXP __CONCATX (PREFIX, _MAX_EXP)
#define MANT_DIG __CONCATX (PREFIX, _MANT_DIG)

/* Format specific test macros.  */
#define TEST_COND_binary32 (MANT_DIG == 24	\
			    && MIN_EXP == -125	\
			    && MAX_EXP == 128)

#define TEST_COND_binary64 (MANT_DIG == 53	\
			    && MIN_EXP == -1021	\
			    && MAX_EXP == 1024)

#define TEST_COND_binary128 (MANT_DIG == 113		\
			     && MIN_EXP == -16381	\
			     && MAX_EXP == 16384)

#define TEST_COND_ibm128 (MANT_DIG == 106)

#define TEST_COND_intel96 (MANT_DIG == 64	\
			   && MIN_EXP == -16381	\
			   && MAX_EXP == 16384)

#define TEST_COND_m68k96 (MANT_DIG == 64	\
			  && MIN_EXP == -16382	\
			  && MAX_EXP == 16384)

/* The condition ibm128-libgcc is used instead of ibm128 to mark tests
   where in principle the glibc code is OK but the tests fail because
   of limitations of the libgcc support for that format (e.g. GCC bug
   59666, in non-default rounding modes).  */
#define TEST_COND_ibm128_libgcc TEST_COND_ibm128

/* Mark a test as expected to fail for ibm128-libgcc.  This is used
   via XFAIL_ROUNDING_IBM128_LIBGCC, which gen-libm-test.pl transforms
   appropriately for each rounding mode.  */
#define XFAIL_IBM128_LIBGCC (TEST_COND_ibm128_libgcc ? XFAIL_TEST : 0)

/* Number of bits in NaN payload.  */
#if TEST_COND_ibm128
# define PAYLOAD_DIG (DBL_MANT_DIG - 2)
#else
# define PAYLOAD_DIG (MANT_DIG - 2)
#endif

/* Values underflowing on architectures detecting tininess before
   rounding, but not on those detecting tininess after rounding.  */
#define UNDERFLOW_EXCEPTION_BEFORE_ROUNDING	(TININESS_AFTER_ROUNDING \
						 ? 0			\
						 : UNDERFLOW_EXCEPTION)

#if LONG_MAX == 0x7fffffff
# define TEST_COND_long32	1
# define TEST_COND_long64	0
#else
# define TEST_COND_long32	0
# define TEST_COND_long64	1
#endif
#define TEST_COND_before_rounding	(!TININESS_AFTER_ROUNDING)
#define TEST_COND_after_rounding	TININESS_AFTER_ROUNDING

int enable_test (int);
void init_max_error (const char *, int);
void print_max_error (const char *);
void print_complex_max_error (const char *);
void check_float (const char *, FLOAT, FLOAT, int);
void check_complex (const char *, __complex__ FLOAT, __complex__ FLOAT, int);
void check_int (const char *, int, int, int);
void check_long (const char *, long int, long int, int);
void check_bool (const char *, int, int, int);
void check_longlong (const char *, long long int, long long int, int);
void check_intmax_t (const char *, intmax_t, intmax_t, int);
void check_uintmax_t (const char *, uintmax_t, uintmax_t, int);
void libm_test_init (int, char **);
int libm_test_finish (void);

#endif /* LIBM_TEST_SUPPORT_H.  */
