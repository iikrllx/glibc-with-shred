/* Copyright (C) 1999, 2000 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

int
do_test (void)
{
  const int family[3] = { AF_INET, AF_INET6, AF_UNIX };
  int result = 0;
  int gaierr, index;
  struct addrinfo hints, *ai, *aitop;

  for (index = 0; index < sizeof (family) / sizeof (family[0]); ++index)
    {
      memset (&hints, '\0', sizeof (hints));
      hints.ai_family = family[index];
      hints.ai_socktype = SOCK_STREAM;

      gaierr = getaddrinfo (NULL, "54321", &hints, &aitop);
      if (gaierr != 0)
	{
	  gai_strerror (gaierr);
	  result = 1;
	}
      else
	{
	  for (ai = aitop; ai != NULL; ai = ai->ai_next)
	    {
	      printf ("Should return family: %d. Returned: %d\n",
		      family[index], ai->ai_family);
	      result |= family[index] != ai->ai_family;
	    }

	  while (aitop != NULL)
	    {
	      ai = aitop;
	      aitop = aitop->ai_next;
	      freeaddrinfo (ai);
	    }
	}
    }

  return result;
}
#define TEST_FUNCTION do_test ()

#include "../test-skeleton.c"
