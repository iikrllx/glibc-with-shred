/* Test program for user-defined character maps.
   Copyright (C) 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>.

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

#include <locale.h>
#include <stdio.h>
#include <wctype.h>

int
main (void)
{
  wctrans_t t;
  wint_t wch;
  int errors = 0;

  setlocale (LC_ALL, "");

  t = wctrans ("test");
  if (t == (wctrans_t) 0)
    exit (1);

  wch = towctrans (L'A', t);
  printf ("towctrans (L'A', t) = %c\n", wch);
  if (wch != L'B')
    errors = 1;

  wch = towctrans (L'B', t);
  printf ("towctrans (L'B', t) = %c\n", wch);
  if (wch != L'C')
    errors = 1;

  return errors;
}
