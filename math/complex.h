/* Copyright (C) 1997, 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/*
 *	ISO C 9X:  7.8 Complex arithmetic	<complex.h>
 */

#ifndef _COMPLEX_H
#define _COMPLEX_H	1

#include <features.h>

/* Get general and ISO C 9X specific information.  */
#include <bits/mathdef.h>

__BEGIN_DECLS

/* We might need to add support for more compilers here.  But once ISO
   C 9X is out hopefully all maintained compilers will provide the data
   types `float complex' and `double complex'.  */
#if (__GNUC__ == 2 && __GNUC_MINOR__ >= 7) || __GNUC__ > 2
# define _Complex __complex__
#endif


/* Narrowest imaginary unit.  This depends on the floating-point
   evaluation method.
   XXX This probably has to go into a gcc related file.  */
#define _Complex_I	(1.0iF)

/* Another more descriptive name is `I'.
   XXX Once we have the imaginary support switch this to _Imaginary_I.  */
#undef I
#define I _Complex_I


/* Optimization aids.  This is not yet implemented in gcc and once it
   is this will probably be available in a gcc header.  */
#define CX_LIMITED_RANGE_ON
#define CX_LIMITED_RANGE_OFF
#define CX_LIMITED_RANGE_DEFAULT


/* The file <bits/cmathcalls.h> contains the prototypes for all the
   actual math functions.  These macros are used for those prototypes,
   so we can easily declare each function as both `name' and `__name',
   and can declare the float versions `namef' and `__namef'.  */

#define __MATHCALL(function, args)	\
  __MATHDECL (_Mdouble_complex_,function, args)
#define __MATHDECL(type, function, args) \
  __MATHDECL_1(type, function, args); \
  __MATHDECL_1(type, __CONCAT(__,function), args)
#define __MATHDECL_1(type, function, args) \
  extern type __MATH_PRECNAME(function) args

#define _Mdouble_ 		double
#define __MATH_PRECNAME(name)	name
#include <bits/cmathcalls.h>
#undef	_Mdouble_
#undef	__MATH_PRECNAME

/* Now the float versions.  */
#ifndef _Mfloat_
# define _Mfloat_		float
#endif
#define _Mdouble_ 		_Mfloat_
#ifdef __STDC__
# define __MATH_PRECNAME(name)	name##f
#else
# define __MATH_PRECNAME(name)	name/**/f
#endif
#include <bits/cmathcalls.h>
#undef	_Mdouble_
#undef	__MATH_PRECNAME

/* And the long double versions.  It is non-critical to define them
   here unconditionally since `long double' is required in ISO C 9X.  */
#if __STDC__ - 0 || __GNUC__ - 0 && !defined __NO_LONG_DOUBLE_MATH
# ifndef _Mlong_double_
#  define _Mlong_double_	long double
# endif
# define _Mdouble_ 		_Mlong_double_
# ifdef __STDC__
#  define __MATH_PRECNAME(name)	name##l
# else
#  define __MATH_PRECNAME(name)	name/**/l
# endif
# include <bits/cmathcalls.h>
#endif
#undef	_Mdouble_
#undef	__MATH_PRECNAME
#undef	__MATHDECL_1
#undef	__MATHDECL
#undef	__MATHCALL

__END_DECLS

#endif /* complex.h */
