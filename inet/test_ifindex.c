/* Test interface name <-> index conversions.
   Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Philip Blundell <Philip.Blundell@pobox.com>.

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

int
main (void)
{
  int failures = 0;
  struct if_nameindex *idx = if_nameindex (), *p;
  if (idx == NULL)
    {
      if (errno != ENOSYS)
	{
	  printf ("Couldn't get any interfaces.\n");
	  exit (1);
	}
      /* The function is simply not implemented.  */
      exit (0);
    }

  printf ("Idx            Name | Idx           Name\n");

  for (p = idx; p->if_index || p->if_name; ++p)
    {
      char buf[IFNAMSIZ];
      int ni, result;
      printf ("%3d %15s | ", p->if_index, p->if_name);
      printf ("%3d", ni = if_nametoindex (p->if_name));
      printf ("%15s", if_indextoname (p->if_index, buf));
      result = (ni != p->if_index || (strcmp (buf, p->if_name)));
      printf ("%10s", result ? "fail" : "okay");
      printf ("\n");
      failures += result;
    }
  if_freenameindex (idx);
  exit (failures ? 1 : 0);
}
