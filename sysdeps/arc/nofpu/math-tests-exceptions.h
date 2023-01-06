/* Configuration for math tests.  Exceptions support ARC version.
   Copyright (C) 2020-2023 Free Software Foundation, Inc.
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

#ifndef ARC_NOFPU_MATH_TESTS_EXCEPTIONS_H
#define ARC_NOFPU_MATH_TESTS_EXCEPTIONS_H 1

/* Soft-float does not support exceptions.  */
#define EXCEPTION_TESTS_float		0
#define EXCEPTION_TESTS_double		0
#define EXCEPTION_TESTS_long_double	0

#endif
