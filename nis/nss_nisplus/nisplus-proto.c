/* Copyright (C) 1997 Free Software Foundation, Inc.
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
   Boston, MA 02111-1307, USA.  */

#include <nss.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <bits/libc-lock.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nislib.h>

#include "nss-nisplus.h"

__libc_lock_define_initialized (static, lock)

static nis_result *result = NULL;
static nis_name tablename_val = NULL;
static u_long tablename_len = 0;

#define NISENTRYVAL(idx,col,res) \
        ((res)->objects.objects_val[(idx)].EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_val)

#define NISENTRYLEN(idx,col,res) \
        ((res)->objects.objects_val[(idx)].EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_len)

static int
_nss_nisplus_parse_protoent (nis_result * result, struct protoent *proto,
			     char *buffer, size_t buflen)
{
  char *first_unused = buffer;
  size_t room_left = buflen;
  unsigned int i;
  char *p, *line;

  if (result == NULL)
    return 0;

  if ((result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) ||
      __type_of (NIS_RES_OBJECT (result)) != ENTRY_OBJ ||
      strcmp (NIS_RES_OBJECT (result)->EN_data.en_type, "protocols_tbl") != 0
      || NIS_RES_OBJECT (result)->EN_data.en_cols.en_cols_len < 3)
    return 0;

  /* Generate the protocols entry format and use the normal parser */
  if (NISENTRYLEN (0, 0, result) + 1 > room_left)
    {
    no_more_room:
      __set_errno (ERANGE);
      return 0;
    }
  strncpy (first_unused, NISENTRYVAL (0, 0, result),
           NISENTRYLEN (0, 0, result));
  first_unused[NISENTRYLEN (0, 0, result)] = '\0';
  proto->p_name = first_unused;
  room_left -= (strlen (first_unused) +1);
  first_unused += strlen (first_unused) +1;


  if (NISENTRYLEN (0, 2, result) + 1 > room_left)
    goto no_more_room;
  proto->p_proto = atoi (NISENTRYVAL (0, 2, result));
  p = first_unused;

  line = p;
  for (i = 0; i < result->objects.objects_len; i++)
    {
      if (strcmp (NISENTRYVAL (i, 1, result), proto->p_name) != 0)
        {
          if (NISENTRYLEN (i, 1, result) + 2 > room_left)
            goto no_more_room;
          p = stpcpy(p, " ");
          p = stpncpy (p, NISENTRYVAL (i, 1, result),
                       NISENTRYLEN (i, 1, result));
          *p = '\0';
          room_left -= (NISENTRYLEN (i, 1, result) + 1);
        }
    }
  ++p;
  first_unused = p;

  /* Adjust the pointer so it is aligned for
     storing pointers.  */
  first_unused += __alignof__ (char *) - 1;
  first_unused -= ((first_unused - (char *) 0) % __alignof__ (char *));
  proto->p_aliases = (char **) first_unused;
  if (room_left < sizeof (char *))
    goto no_more_room;
  room_left -= (sizeof (char *));
  proto->p_aliases[0] = NULL;

  i = 0;
  while (*line != '\0')
    {
      /* Skip leading blanks.  */
      while (isspace (*line))
        line++;
      if (*line == '\0')
        break;

      if (room_left < sizeof (char *))
        goto no_more_room;

      room_left -= sizeof (char *);
      proto->p_aliases[i] = line;

      while (*line != '\0' && *line != ' ')
        ++line;

      if (*line == ' ')
        {
          *line = '\0';
          ++line;
          ++i;
        }
      else
        proto->p_aliases[i+1] = NULL;
    }

  return 1;
}

static enum nss_status
_nss_create_tablename (void)
{
  if (tablename_val == NULL)
    {
      char buf [40 + strlen (nis_local_directory ())];
      char *p;

      p = stpcpy (buf, "protocols.org_dir.");
      p = stpcpy (p, nis_local_directory ());
      tablename_val = strdup (buf);
      if (tablename_val == NULL)
        return NSS_STATUS_TRYAGAIN;
      tablename_len = strlen (tablename_val);
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_setprotoent (void)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;

  if (tablename_val == NULL)
    status = _nss_create_tablename ();

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_endprotoent (void)
{
  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_nisplus_getprotoent_r (struct protoent *proto, char *buffer,
				size_t buflen)
{
  int parse_res;

  /* Get the next entry until we found a correct one. */
  do
    {
      if (result == NULL)
	{
	  if (tablename_val == NULL)
	    if (_nss_create_tablename () != NSS_STATUS_SUCCESS)
	      return NSS_STATUS_UNAVAIL;

	  result = nis_first_entry (tablename_val);
	  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	    return niserr2nss (result->status);
	}
      else
	{
	  nis_result *res;

	  res = nis_next_entry (tablename_val, &result->cookie);
	  nis_freeresult (result);
	  result = res;

	  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	    return niserr2nss (result->status);
	}

      parse_res = _nss_nisplus_parse_protoent (result, proto, buffer, buflen);
    }
  while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_getprotoent_r (struct protoent *result, char *buffer,
			    size_t buflen)
{
  int status;

  __libc_lock_lock (lock);

  status = internal_nisplus_getprotoent_r (result, buffer, buflen);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_getprotobyname_r (const char *name, struct protoent *proto,
			       char *buffer, size_t buflen)
{
  int parse_res;

  if (tablename_val == NULL)
    if (_nss_create_tablename () != NSS_STATUS_SUCCESS)
      return NSS_STATUS_UNAVAIL;

  if (name == NULL)
    return NSS_STATUS_NOTFOUND;
  else
    {
      nis_result *result;
      char buf[strlen (name) + 255 + tablename_len];

      /* Search at first in the alias list, and use the correct name
         for the next search */
      sprintf (buf, "[name=%s],%s", name, tablename_val);
      result = nis_list (buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

      /* If we do not find it, try it as original name. But if the
         database is correct, we should find it in the first case, too */
      if ((result->status != NIS_SUCCESS &&
	   result->status != NIS_S_SUCCESS) ||
	  __type_of (result->objects.objects_val) != ENTRY_OBJ ||
	  strcmp (result->objects.objects_val->EN_data.en_type,
		  "protocols_tbl") != 0 ||
	  result->objects.objects_val->EN_data.en_cols.en_cols_len < 3)
	sprintf (buf, "[cname=%s],%s", name, tablename_val);
      else
	sprintf (buf, "[cname=%s],%s", NISENTRYVAL (0, 0, result),
		 tablename_val);

      nis_freeresult (result);
      result = nis_list (buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

      if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	{
	  enum nss_status status = niserr2nss (result->status);

	  nis_freeresult (result);
	  return status;
	}

      parse_res = _nss_nisplus_parse_protoent (result, proto, buffer, buflen);

      nis_freeresult (result);

      if (parse_res)
	return NSS_STATUS_SUCCESS;

      if (!parse_res && errno == ERANGE)
	return NSS_STATUS_TRYAGAIN;
      else
	return NSS_STATUS_NOTFOUND;
    }
}

enum nss_status
_nss_nisplus_getprotobynumber_r (const int number, struct protoent *proto,
				 char *buffer, size_t buflen)
{
  if (tablename_val == NULL)
    if (_nss_create_tablename () != NSS_STATUS_SUCCESS)
      return NSS_STATUS_UNAVAIL;
  {
    int parse_res;
    nis_result *result;
    char buf[46 + tablename_len];

    snprintf (buf, sizeof (buf), "[number=%d],%s", number, tablename_val);

    result = nis_list (buf, FOLLOW_LINKS | FOLLOW_PATH, NULL, NULL);

    if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
      {
	enum nss_status status = niserr2nss (result->status);

	nis_freeresult (result);
	return status;
      }

    parse_res = _nss_nisplus_parse_protoent (result, proto, buffer, buflen);

    nis_freeresult (result);
    if (parse_res)
      return NSS_STATUS_SUCCESS;

    if (!parse_res && errno == ERANGE)
      return NSS_STATUS_TRYAGAIN;
    else
      return NSS_STATUS_NOTFOUND;
  }
}
