/* Copyright (c) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1997.

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
   Boston, MA 02111-1307, USA. */

#include <string.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nislib.h>

void
nis_print_group_entry (const_nis_name group)
{
  if (group != NULL && strlen (group) > 0)
    {
      char buf[strlen (group) + 50];
      char leafbuf[strlen (group) + 3];
      char domainbuf[strlen (group) + 3];
      nis_result *res;
      char *cp, *cp2;
      u_int i;

      cp = stpcpy (buf, nis_leaf_of_r (group, leafbuf, sizeof (leafbuf) - 1));
      cp = stpcpy (cp, ".groups_dir");
      cp2 = nis_domain_of_r (group, domainbuf, sizeof (domainbuf) - 1);
      if (cp2 != NULL && strlen (cp2) > 0)
	{
	  cp = stpcpy (cp, ".");
	  strcpy (cp, cp2);
	}
      res = nis_lookup (buf, FOLLOW_LINKS|EXPAND_NAME);

      if (res->status != NIS_SUCCESS && res->status != NIS_S_SUCCESS)
	return;

      if ((res->objects.objects_len != 1) ||
          (res->objects.objects_val[0].zo_data.zo_type != GROUP_OBJ))
	return;

      for (i = 0;
	   i < res->objects.objects_val[0].GR_data.gr_members.gr_members_len;
	   ++i)
	fprintf (stdout, "  %s\n",
		 res->objects.objects_val[0].GR_data.gr_members.gr_members_val[i]);
    }
}
