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
#include <libc-lock.h>
#include <rpc/netdb.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nislib.h>

#include "nss-nisplus.h"

__libc_lock_define_initialized (static, lock)

static nis_result *result = NULL;
static nis_name *names = NULL;

#define ENTNAME         rpcent
#define DATABASE        "rpc"
#define TRAILING_LIST_MEMBER            r_aliases
#define TRAILING_LIST_SEPARATOR_P       isspace
#include "../../nss/nss_files/files-parse.c"
LINE_PARSER
("#",
 STRING_FIELD (result->r_name, isspace, 1);
 INT_FIELD (result->r_number, isspace, 1, 10,);
 )

#define NISENTRYVAL(idx,col,res) \
        ((res)->objects.objects_val[(idx)].zo_data.objdata_u.en_data.en_cols.en_cols_val[(col)].ec_value.ec_value_val)

#define NISENTRYLEN(idx,col,res) \
        ((res)->objects.objects_val[(idx)].zo_data.objdata_u.en_data.en_cols.en_cols_val[(col)].ec_value.ec_value_len)

static int
_nss_nisplus_parse_rpcent (nis_result *result, struct rpcent *rpc,
			   char *buffer, size_t buflen)
{
  char *p = buffer;
  size_t room_left = buflen;
  int i;
  struct parser_data *data = (void *) buffer;

  if (result == NULL)
    return 0;

  if ((result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) ||
      result->objects.objects_val[0].zo_data.zo_type != ENTRY_OBJ ||
      strcmp(result->objects.objects_val[0].zo_data.objdata_u.en_data.en_type,
             "rpc_tbl") != 0 ||
      result->objects.objects_val[0].zo_data.objdata_u.en_data.en_cols.en_cols_len < 3)
    return 0;

  memset (p, '\0', room_left);

  /* Generate the rpc entry format and use the normal parser */
  if (NISENTRYLEN (0, 0, result) +1 > room_left)
    {
      __set_errno (ERANGE);
      return 0;
    }
  strncpy (p, NISENTRYVAL (0, 0, result), NISENTRYLEN (0, 0, result));
  room_left -= (NISENTRYLEN (0, 0, result) +1);

  if (NISENTRYLEN (0, 2, result) +1 > room_left)
    {
      __set_errno (ERANGE);
      return 0;
    }
  strcat (p, "\t");
  strncat (p, NISENTRYVAL (0, 2, result), NISENTRYLEN (0, 2, result));
  room_left -= (NISENTRYLEN (0, 2, result) + 1);
                                       /* + 1: We overwrite the last \0 */

  for (i = 0; i < result->objects.objects_len; i++)
    /* XXX should we start with i = 0 or with i = 1 ? */
    {
      if (NISENTRYLEN (i, 1, result) +1 > room_left)
        {
          __set_errno (ERANGE);
          return 0;
        }
      strcat (p, " ");
      strncat (p, NISENTRYVAL (i, 1, result), NISENTRYLEN (i, 1, result));
      room_left -= (NISENTRYLEN (i, 1, result) + 1);
    }

  return _nss_files_parse_rpcent (p, rpc, data, buflen);
}

enum nss_status
_nss_nisplus_setrpcent (void)
{
  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;
  if (names)
    {
      nis_freenames (names);
      names = NULL;
    }

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_endrpcent (void)
{
  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;
  if (names)
    {
      nis_freenames (names);
      names = NULL;
    }

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_nisplus_getrpcent_r (struct rpcent *rpc, char *buffer,
			      size_t buflen)
{
  int parse_res;

  /* Get the next entry until we found a correct one. */
  do
    {
      if (result == NULL)
	{
	  names = nis_getnames ("rpc.org_dir");
	  if (names == NULL || names[0] == NULL)
	    return NSS_STATUS_UNAVAIL;

	  result = nis_first_entry(names[0]);
	  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	    return niserr2nss (result->status);
	}
      else
	{
	  nis_result *res;

	  res = nis_next_entry (names[0], &result->cookie);
	  nis_freeresult (result);
	  result = res;
	  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	    return niserr2nss (result->status);
	}

      parse_res = _nss_nisplus_parse_rpcent (result, rpc, buffer, buflen);
    } while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_getrpcent_r (struct rpcent *result, char *buffer,
			  size_t buflen)
{
  int status;

  __libc_lock_lock (lock);

  status = internal_nisplus_getrpcent_r (result, buffer, buflen);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_getrpcbyname_r (const char *name, struct rpcent *rpc,
			     char *buffer, size_t buflen)
{
  int parse_res;

  if (name == NULL)
    return NSS_STATUS_NOTFOUND;
  else
    {
      nis_result *result;
      char buf[strlen (name) + 255];

      /* Search at first in the alias list, and use the correct name
         for the next search */
      sprintf (buf, "[name=%s],rpc.org_dir", name);
      result = nis_list (buf, EXPAND_NAME, NULL, NULL);

      /* If we do not find it, try it as original name. But if the
         database is correct, we should find it in the first case, too */
      if ((result->status != NIS_SUCCESS &&
           result->status != NIS_S_SUCCESS) ||
          result->objects.objects_val[0].zo_data.zo_type != ENTRY_OBJ ||
          strcmp (result->objects.objects_val[0].zo_data.objdata_u.en_data.en_type,
		  "rpc_tbl") != 0 ||
          result->objects.objects_val[0].zo_data.objdata_u.en_data.en_cols.en_cols_len < 3)
        sprintf (buf, "[cname=%s],rpc.org_dir", name);
      else
        sprintf (buf, "[cname=%s],rpc.org_dir", NISENTRYVAL(0, 0, result));

      nis_freeresult (result);
      result = nis_list(buf, EXPAND_NAME, NULL, NULL);

      if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
	{
	  enum nss_status status = niserr2nss (result->status);

	  nis_freeresult (result);
	  return status;
	}

      parse_res = _nss_nisplus_parse_rpcent (result, rpc, buffer, buflen);

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
_nss_nisplus_getrpcbynumber_r (const int number, struct rpcent *rpc,
				char *buffer, size_t buflen)
{
  int parse_res;
  nis_result *result;
  char buf[100];

  snprintf (buf, sizeof (buf), "[number=%d],rpc.org_dir", number);

  result = nis_list(buf, EXPAND_NAME, NULL, NULL);

  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
    {
      enum nss_status status = niserr2nss (result->status);

      nis_freeresult (result);
      return status;
    }

  parse_res = _nss_nisplus_parse_rpcent (result, rpc, buffer, buflen);

  nis_freeresult (result);

  if (parse_res)
    return NSS_STATUS_SUCCESS;

  if (!parse_res && errno == ERANGE)
    return NSS_STATUS_TRYAGAIN;
  else
    return NSS_STATUS_NOTFOUND;
}
