/* Copyright (C) 1991, 1996 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <errno.h>
#include <limits.h>
#include <printf.h>

/* Array of functions indexed by format character.  */
static printf_function *printf_funcs[UCHAR_MAX + 1];
printf_arginfo_function *__printf_arginfo_table[UCHAR_MAX + 1];

printf_function **__printf_function_table;

int __register_printf_function __P ((int, printf_function,
                                     printf_arginfo_function));

/* Register FUNC to be called to format SPEC specifiers.  */
int
__register_printf_function (spec, converter, arginfo)
     int spec;
     printf_function converter;
     printf_arginfo_function arginfo;
{
  if (spec < 0 || spec > (int) UCHAR_MAX)
    {
      __set_errno (EINVAL);
      return -1;
    }

  __printf_function_table = printf_funcs;
  __printf_arginfo_table[spec] = arginfo;
  printf_funcs[spec] = converter;

  return 0;
}
weak_alias (__register_printf_function, register_printf_function)
