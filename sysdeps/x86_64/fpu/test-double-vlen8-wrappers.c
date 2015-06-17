/* Wrapper part of tests for AVX-512 versions of vector math functions.
   Copyright (C) 2014-2015 Free Software Foundation, Inc.
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

#include "test-double-vlen8.h"
#include "test-vec-loop.h"
#include <immintrin.h>

#define VEC_TYPE __m512d

VECTOR_WRAPPER (WRAPPER_NAME (cos), _ZGVeN8v_cos)
VECTOR_WRAPPER (WRAPPER_NAME (sin), _ZGVeN8v_sin)
VECTOR_WRAPPER (WRAPPER_NAME (log), _ZGVeN8v_log)
VECTOR_WRAPPER (WRAPPER_NAME (exp), _ZGVeN8v_exp)
VECTOR_WRAPPER_ff (WRAPPER_NAME (pow), _ZGVeN8vv_pow)
