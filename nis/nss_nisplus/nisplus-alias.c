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
#include <string.h>
#include <aliases.h>
#include <bits/libc-lock.h>
#include <rpcsvc/nis.h>

#include "nss-nisplus.h"

__libc_lock_define_initialized (static, lock)

static nis_result *result = NULL;
static u_long next_entry = 0;
static nis_name tablename_val = NULL;
static u_long tablename_len = 0;

#define NISENTRYVAL(idx,col,res) \
        ((res)->objects.objects_val[(idx)].EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_val)

#define NISENTRYLEN(idx,col,res) \
        ((res)->objects.objects_val[(idx)].EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_len)

static enum nss_status
_nss_create_tablename (void)
{
  if (tablename_val == NULL)
    {
      char buf [40 + strlen (nis_local_directory ())];
      char *p;

      p = stpcpy (buf, "mail_aliases.org_dir.");
      p = stpcpy (p, nis_local_directory ());
      tablename_val = strdup (buf);
      if (tablename_val == NULL)
        return NSS_STATUS_TRYAGAIN;
      tablename_len = strlen (tablename_val);
    }
  return NSS_STATUS_SUCCESS;
}

static int
_nss_nisplus_parse_aliasent (nis_result *result, unsigned long entry,
			     struct aliasent *alias, char *buffer,
			     size_t buflen)
{
  if (result == NULL)
    return 0;

  if ((result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) ||
      __type_of (&result->objects.objects_val[entry]) != ENTRY_OBJ ||
      strcmp(result->objects.objects_val[entry].EN_data.en_type,
	     "mail_aliases") != 0 ||
      result->objects.objects_val[entry].EN_data.en_cols.en_cols_len < 2)
    return 0;
  else
    {
      char *first_unused = buffer + NISENTRYLEN(0, 1, result) + 1;
      size_t room_left =
	buflen - (buflen % __alignof__ (char *)) -
	NISENTRYLEN(0, 1, result) - 2;
      char *line;
      char *cp;

      if (NISENTRYLEN(entry, 1, result) >= buflen)
	{
	  /* The line is too long for our buffer.  */
	no_more_room:
	  __set_errno (ERANGE);
	  return -1;
	}
      else
	{
	  strncpy (buffer, NISENTRYVAL(entry, 1, result),
		   NISENTRYLEN(entry, 1, result));
	  buffer[NISENTRYLEN(entry, 1, result)] = '\0';
	}

      if (NISENTRYLEN(entry, 0, result) >= room_left)
	goto no_more_room;

      alias->alias_local = 0;
      alias->alias_members_len = 0;
      *first_unused = '\0';
      ++first_unused;
      strcpy (first_unused, NISENTRYVAL(entry, 0, result));
      first_unused[NISENTRYLEN(entry, 0, result)] = '\0';
      alias->alias_name = first_unused;

      /* Terminate the line for any case.  */
      cp = strpbrk (alias->alias_name, "#\n");
      if (cp != NULL)
	*cp = '\0';

      first_unused += strlen (alias->alias_name) +1;
      /* Adjust the pointer so it is aligned for
	 storing pointers.  */
      first_unused += __alignof__ (char *) - 1;
      first_unused -= ((first_unused - (char *) 0) % __alignof__ (char *));
      alias->alias_members = (char **) first_unused;

      line = buffer;

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
	  alias->alias_members[alias->alias_members_len] = line;

	  while (*line != '\0' && *line != ',')
	    line++;

	  if (line != alias->alias_members[alias->alias_members_len])
	    {
	      *line = '\0';
	      line++;
	      alias->alias_members_len++;
	    }
	}

      return alias->alias_members_len == 0 ? 0 : 1;
    }
}

static enum nss_status
internal_setaliasent (void)
{
  enum nss_status status;

  if (result)
    nis_freeresult (result);
  result = NULL;

  if (_nss_create_tablename () != NSS_STATUS_SUCCESS)
    return NSS_STATUS_UNAVAIL;

  next_entry = 0;
  result = nis_list(tablename_val, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
  status = niserr2nss (result->status);
  if (status != NSS_STATUS_SUCCESS)
    {
      nis_freeresult (result);
      result = NULL;
    }
  return status;
}

enum nss_status
_nss_nisplus_setaliasent (void)
{
  enum nss_status status;

  __libc_lock_lock (lock);

  status = internal_setaliasent ();

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_endaliasent (void)
{
  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;
  next_entry = 0;

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_nisplus_getaliasent_r (struct aliasent *alias,
				char *buffer, size_t buflen)
{
  int parse_res;

  if (result == NULL)
    {
      enum nss_status status;

      status = internal_setaliasent ();
      if (result == NULL || status != NSS_STATUS_SUCCESS)
	return status;
    }

  /* Get the next entry until we found a correct one. */
  do
    {
      if (next_entry >= result->objects.objects_len)
	return NSS_STATUS_NOTFOUND;

      if ((parse_res = _nss_nisplus_parse_aliasent (result, next_entry, alias,
						    buffer, buflen)) == -1)
	return NSS_STATUS_TRYAGAIN;

      ++next_entry;
    } while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_getaliasent_r (struct aliasent *result, char *buffer,
			    size_t buflen)
{
  int status;

  __libc_lock_lock (lock);

  status = internal_nisplus_getaliasent_r (result, buffer, buflen);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_getaliasbyname_r (const char *name, struct aliasent *alias,
			    char *buffer, size_t buflen)
{
  int parse_res;

  if (tablename_val == NULL)
    if (_nss_create_tablename() != NSS_STATUS_SUCCESS)
      return NSS_STATUS_UNAVAIL;

  if (name != NULL || strlen(name) <= 8)
    {
      nis_result *result;
      char buf[strlen (name) + 30 + tablename_len];

      sprintf(buf, "[name=%s],%s", name, tablename_val);

      result = nis_list(buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

      if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	return niserr2nss (result->status);

      if ((parse_res = _nss_nisplus_parse_aliasent (result, 0, alias,
						    buffer, buflen)) == -1)
	return NSS_STATUS_TRYAGAIN;

      if (parse_res)
	return NSS_STATUS_SUCCESS;
    }
  return NSS_STATUS_NOTFOUND;
}
