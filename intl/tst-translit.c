/* Test of translitation in the gettext functions.
   Copyright (C) 2000 Free Software Foundation, Inc.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 2000.

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

#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main (void)
{
  int result = 0;
  const char *s;

  setenv ("LANGUAGE", "existing-locale", 1);
  unsetenv ("OUTPUT_CHARSET");
  setlocale (LC_ALL, "en_US.ANSI_X3.4-1968");
  textdomain ("translit");
  bindtextdomain ("translit", OBJPFX "domaindir");

#define TEST(in, exp) \
  s = gettext (in);							      \
  puts (s);								      \
  result |= strcmp (s, exp) != 0;

  TEST ("test", "<<(C) AEss>>");
  TEST ("test", "<<(C) AEss>>");
  TEST ("onemore", " 1/2 * 1/2 = 1/4 ");
  TEST ("onemore", " 1/2 * 1/2 = 1/4 ");
  TEST ("test", "<<(C) AEss>>");

  return result;
}
