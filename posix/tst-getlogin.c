/* Copyright (C) 1999 Free Software Foundation, Inc.
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

#include <unistd.h>
#include <stdio.h>
#include <string.h>

int
main (void)
{
  char *login;
  int errors = 0;

  login = getlogin ();
  if (login == NULL)
    puts ("getlogin returned NULL, no further tests");
  else
    {
      char name[1024];
      int ret;

      printf ("getlogin returned: `%s'\n", login);

      ret = getlogin_r (name, sizeof (name));
      if (ret == 0)
	{
	  printf ("getlogin_r returned: `%s'\n", name);
	  if (strcmp (name, login) != 0)
	    {
	      puts ("Error: getlogin and getlogin_r returned different names");
	      ++errors;
	    }
	}
      else
	{
	  printf ("Error: getlogin_r returned: %d (%s)\n",
		  ret, strerror (ret));
	  ++errors;
	}
    }

  return errors != 0;
}
