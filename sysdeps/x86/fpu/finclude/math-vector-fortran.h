! Platform-specific declarations of SIMD math functions for Fortran. -*- f90 -*-
!   Copyright (C) 2019-2021 Free Software Foundation, Inc.
!   This file is part of the GNU C Library.
!
!   The GNU C Library is free software; you can redistribute it and/or
!   modify it under the terms of the GNU Lesser General Public
!   License as published by the Free Software Foundation; either
!   version 2.1 of the License, or (at your option) any later version.
!
!   The GNU C Library is distributed in the hope that it will be useful,
!   but WITHOUT ANY WARRANTY; without even the implied warranty of
!   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
!   Lesser General Public License for more details.
!
!   You should have received a copy of the GNU Lesser General Public
!   License along with the GNU C Library; if not, see
!   <https://www.gnu.org/licenses/>.

!GCC$ builtin (cos) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (cosf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (sin) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (sinf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (sincos) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (sincosf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (log) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (logf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (exp) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (expf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (pow) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (powf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (acos) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (acosf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (atan) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (atanf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (asin) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (asinf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (hypot) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (hypotf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (exp2) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (exp2f) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (exp10) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (exp10f) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (cosh) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (coshf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (expm1) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (expm1f) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (sinh) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (sinhf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (cbrt) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (cbrtf) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (atan2) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (atan2f) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (log10) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (log10f) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (log2) attributes simd (notinbranch) if('x86_64')
!GCC$ builtin (log2f) attributes simd (notinbranch) if('x86_64')

!GCC$ builtin (cos) attributes simd (notinbranch) if('x32')
!GCC$ builtin (cosf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (sin) attributes simd (notinbranch) if('x32')
!GCC$ builtin (sinf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (sincos) attributes simd (notinbranch) if('x32')
!GCC$ builtin (sincosf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (log) attributes simd (notinbranch) if('x32')
!GCC$ builtin (logf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (exp) attributes simd (notinbranch) if('x32')
!GCC$ builtin (expf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (pow) attributes simd (notinbranch) if('x32')
!GCC$ builtin (powf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (acos) attributes simd (notinbranch) if('x32')
!GCC$ builtin (acosf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (atan) attributes simd (notinbranch) if('x32')
!GCC$ builtin (atanf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (asin) attributes simd (notinbranch) if('x32')
!GCC$ builtin (asinf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (hypot) attributes simd (notinbranch) if('x32')
!GCC$ builtin (hypotf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (exp2) attributes simd (notinbranch) if('x32')
!GCC$ builtin (exp2f) attributes simd (notinbranch) if('x32')
!GCC$ builtin (exp10) attributes simd (notinbranch) if('x32')
!GCC$ builtin (exp10f) attributes simd (notinbranch) if('x32')
!GCC$ builtin (cosh) attributes simd (notinbranch) if('x32')
!GCC$ builtin (coshf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (expm1) attributes simd (notinbranch) if('x32')
!GCC$ builtin (expm1f) attributes simd (notinbranch) if('x32')
!GCC$ builtin (sinh) attributes simd (notinbranch) if('x32')
!GCC$ builtin (sinhf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (cbrt) attributes simd (notinbranch) if('x32')
!GCC$ builtin (cbrtf) attributes simd (notinbranch) if('x32')
!GCC$ builtin (atan2) attributes simd (notinbranch) if('x32')
!GCC$ builtin (atan2f) attributes simd (notinbranch) if('x32')
!GCC$ builtin (log10) attributes simd (notinbranch) if('x32')
!GCC$ builtin (log10f) attributes simd (notinbranch) if('x32')
!GCC$ builtin (log2) attributes simd (notinbranch) if('x32')
!GCC$ builtin (log2f) attributes simd (notinbranch) if('x32')
