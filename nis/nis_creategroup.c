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

nis_error
nis_creategroup (const_nis_name group, u_long flags)
{
  if (group != NULL && strlen (group) > 0)
    {
      char buf[strlen (group) + 50];
      char leafbuf[strlen (group) + 2];
      char domainbuf[strlen (group) + 2];
      nis_error status;
      nis_result *res;
      char *cp, *cp2;
      nis_object *obj;

      cp = stpcpy (buf, nis_leaf_of_r (group, leafbuf, sizeof (leafbuf) - 1));
      cp = stpcpy (cp, ".groups_dir");
      cp2 = nis_domain_of_r (group, domainbuf, sizeof (domainbuf) - 1);
      if (cp2 != NULL && strlen (cp2) > 0)
        {
	  *cp++ = '.';
          stpcpy (cp, cp2);
        }
      else
	return NIS_BADNAME;

      obj = calloc (1, sizeof (nis_object));
      obj->zo_owner = strdup (__nis_default_owner (NULL));
      obj->zo_group = strdup (__nis_default_group (NULL));
      obj->zo_access = __nis_default_access (NULL, 0);
      obj->zo_ttl = __nis_default_ttl (0);
      obj->zo_data.zo_type = GROUP_OBJ;
      obj->zo_data.objdata_u.gr_data.gr_flags = flags;
      obj->zo_data.objdata_u.gr_data.gr_members.gr_members_len = 0;
      obj->zo_data.objdata_u.gr_data.gr_members.gr_members_val = NULL;

      res = nis_add (buf, obj);
      status = res->status;
      nis_freeresult (res);
      nis_free_object (obj);

      return status;
    }
  return NIS_FAIL;
}
