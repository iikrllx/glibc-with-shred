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
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bits/libc-lock.h>
#include <rpcsvc/nis.h>

#include "nss-nisplus.h"

__libc_lock_define_initialized (static, lock)

static nis_result *result = NULL;
static nis_name tablename_val = NULL;
static u_long tablename_len = 0;

#define NISENTRYVAL(idx,col,res) \
        ((res)->objects.objects_val[(idx)].EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_val)

#define NISENTRYLEN(idx,col,res) \
        ((res)->objects.objects_val[(idx)].EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_len)

/* Get implementation for some internal functions. */
#include "../../resolv/mapv4v6addr.h"

static int
_nss_nisplus_parse_hostent (nis_result *result, int af, struct hostent *host,
			    char *buffer, size_t buflen)
{
  unsigned int i;
  char *first_unused = buffer;
  size_t room_left = buflen;
  char *data, *p, *line;

  if (result == NULL)
    return 0;

  if ((result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) ||
      __type_of (result->objects.objects_val) != NIS_ENTRY_OBJ ||
      strcmp(result->objects.objects_val[0].EN_data.en_type,
	     "hosts_tbl") != 0 ||
      result->objects.objects_val[0].EN_data.en_cols.en_cols_len < 4)
    return 0;

  if (room_left < NISENTRYLEN (0, 2, result) + 1)
    {
    no_more_room:
      __set_errno (ERANGE);
      return -1;
    }

  data = first_unused;
  if (inet_pton (af, NISENTRYVAL (0, 2, result), data) < 1)
    /* Illegal address: ignore line.  */
    return 0;

  host->h_addrtype = af;
  if (af == AF_INET6)
    host->h_length = IN6ADDRSZ;
  else
    {
      if (_res.options & RES_USE_INET6)
	{
	  map_v4v6_address (data, data);
	  host->h_addrtype = AF_INET6;
	  host->h_length = IN6ADDRSZ;
	}
      else
	{
	  host->h_addrtype = AF_INET;
	  host->h_length = INADDRSZ;
	}
    }
  first_unused+=host->h_length;
  room_left-=host->h_length;

  if (NISENTRYLEN (0, 0, result) + 1 > room_left)
    goto no_more_room;

  p = __stpncpy (first_unused, NISENTRYVAL (0, 0, result),
		 NISENTRYLEN (0, 0, result));
  *p = '\0';
  room_left -= (NISENTRYLEN (0, 0, result) + 1);
  host->h_name = first_unused;
  first_unused += NISENTRYLEN (0, 0, result) +1;
  p = first_unused;

  line = p;
  for (i = 0; i < result->objects.objects_len; i++)
    {
      if (strcmp (NISENTRYVAL (i, 1, result), host->h_name) != 0)
	{
	  if (NISENTRYLEN (i, 1, result) + 2 > room_left)
	    goto no_more_room;

	  *p++ = ' ';
	  p = __stpncpy (p, NISENTRYVAL (i, 1, result),
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
  host->h_addr_list = (char **) first_unused;
  if (room_left < 2 * sizeof (char *))
    goto no_more_room;

  room_left -= (2 * sizeof (char *));
  host->h_addr_list[0] = data;
  host->h_addr_list[1] = NULL;
  host->h_aliases = &host->h_addr_list[2];
  host->h_aliases[0] = NULL;

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
      host->h_aliases[i] = line;

      while (*line != '\0' && *line != ' ')
	++line;

      if (*line == ' ')
	{
	  *line = '\0';
	  ++line;
	  ++i;
	}
      else
	host->h_aliases[i+1] = NULL;
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

      p = __stpcpy (buf, "hosts.org_dir.");
      p = __stpcpy (p, nis_local_directory ());
      tablename_val = __strdup (buf);
      if (tablename_val == NULL)
        return NSS_STATUS_TRYAGAIN;
      tablename_len = strlen (tablename_val);
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_sethostent (void)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;

  if (tablename_val == NULL)
    if (_nss_create_tablename() != NSS_STATUS_SUCCESS)
      status = NSS_STATUS_UNAVAIL;

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_endhostent (void)
{
  __libc_lock_lock (lock);

  if (result)
    nis_freeresult (result);
  result = NULL;

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_nisplus_gethostent_r (struct hostent *host, char *buffer,
			       size_t buflen, int *herrnop)
{
  int parse_res;

  /* Get the next entry until we found a correct one. */
  do
    {
      nis_result *saved_res;

      if (result == NULL)
	{
	  saved_res = NULL;
	  if (tablename_val == NULL)
	    if (_nss_create_tablename() != NSS_STATUS_SUCCESS)
	      return NSS_STATUS_UNAVAIL;

	  result = nis_first_entry(tablename_val);
	  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
            {
              enum nss_status retval = niserr2nss (result->status);
              if (retval == NSS_STATUS_TRYAGAIN)
                {
                  *herrnop = NETDB_INTERNAL;
                  __set_errno (EAGAIN);
                }
              return retval;
            }

	}
      else
	{
	  nis_result *res2;

	  saved_res = result;
	  res2 = nis_next_entry(tablename_val, &result->cookie);
	  result = res2;
	  if (niserr2nss (result->status) != NSS_STATUS_SUCCESS)
            {
              enum nss_status retval= niserr2nss (result->status);

	      nis_freeresult (result);
	      result = saved_res;
              if (retval == NSS_STATUS_TRYAGAIN)
                {
                  *herrnop = NETDB_INTERNAL;
                  __set_errno (EAGAIN);
                }
              return retval;
            }
	}

      parse_res = _nss_nisplus_parse_hostent (result, AF_INET6,
					      host, buffer, buflen);
      if (parse_res < 1 && errno != ERANGE)
	parse_res = _nss_nisplus_parse_hostent (result, AF_INET, host,
						buffer, buflen);
      if (parse_res < 1 && errno == ERANGE)
        {
	  nis_freeresult (result);
	  result = saved_res;
          *herrnop = NETDB_INTERNAL;
          return NSS_STATUS_TRYAGAIN;
        }
      if (saved_res != NULL)
	nis_freeresult (saved_res);

    } while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_gethostent_r (struct hostent *result, char *buffer,
			   size_t buflen, int *herrnop)
{
  int status;

  __libc_lock_lock (lock);

  status = internal_nisplus_gethostent_r (result, buffer, buflen, herrnop);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_gethostbyname2_r (const char *name, int af, struct hostent *host,
			      char *buffer, size_t buflen, int *herrnop)
{
  int parse_res, retval;

  if (tablename_val == NULL)
    if (_nss_create_tablename() != NSS_STATUS_SUCCESS)
      {
	*herrnop = NETDB_INTERNAL;
	return NSS_STATUS_UNAVAIL;
      }

  if (name == NULL)
    {
      __set_errno (EINVAL);
      *herrnop = NETDB_INTERNAL;
      return NSS_STATUS_NOTFOUND;
    }
  else
    {
      nis_result *result;
      char buf[strlen (name) + 255 + tablename_len];

      /* Search at first in the alias list, and use the correct name
	 for the next search */
      sprintf(buf, "[name=%s],%s", name, tablename_val);
      result = nis_list(buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

      /* If we do not find it, try it as original name. But if the
	 database is correct, we should find it in the first case, too */
      if ((result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) ||
	  __type_of (result->objects.objects_val) != NIS_ENTRY_OBJ ||
	  strcmp(result->objects.objects_val->EN_data.en_type,
		 "hosts_tbl") != 0 ||
	  result->objects.objects_val->EN_data.en_cols.en_cols_len < 3)
	sprintf(buf, "[cname=%s],%s", name, tablename_val);
      else
	sprintf(buf, "[cname=%s],%s", NISENTRYVAL(0, 0, result),
		tablename_val);

      nis_freeresult (result);
      result = nis_list(buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

      retval = niserr2nss (result->status);
      if (retval != NSS_STATUS_SUCCESS)
        {
          if (retval == NSS_STATUS_TRYAGAIN)
            {
              __set_errno (EAGAIN);
              *herrnop = NETDB_INTERNAL;
            }
	  nis_freeresult (result);
          return retval;
        }

      parse_res =
	_nss_nisplus_parse_hostent (result, af, host, buffer, buflen);

      nis_freeresult (result);

      if (parse_res > 0)
	return NSS_STATUS_SUCCESS;

      *herrnop = NETDB_INTERNAL;
      if (parse_res == -1)
	return NSS_STATUS_TRYAGAIN;
      else
	return NSS_STATUS_NOTFOUND;
    }
}

enum nss_status
_nss_nisplus_gethostbyname_r (const char *name, struct hostent *host,
			      char *buffer, size_t buflen, int *h_errnop)
{
  if (_res.options & RES_USE_INET6)
    {
      enum nss_status status;

      status = _nss_nisplus_gethostbyname2_r (name, AF_INET6, host, buffer,
					      buflen, h_errnop);
      if (status == NSS_STATUS_SUCCESS)
        return status;
    }

  return _nss_nisplus_gethostbyname2_r (name, AF_INET, host, buffer,
					buflen, h_errnop);
}

enum nss_status
_nss_nisplus_gethostbyaddr_r (const char *addr, int addrlen, int type,
			      struct hostent *host, char *buffer,
			      size_t buflen, int *herrnop)
{
  if (tablename_val == NULL)
    if (_nss_create_tablename() != NSS_STATUS_SUCCESS)
      return NSS_STATUS_UNAVAIL;

  if (addr == NULL)
    return NSS_STATUS_NOTFOUND;
  else
    {
      nis_result *result;
      char buf[255 + tablename_len];
      int retval, parse_res;

      sprintf (buf, "[addr=%s],%s",
	       inet_ntoa (*(struct in_addr *)addr), tablename_val);
      result = nis_list(buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

      retval = niserr2nss (result->status);
      if (retval != NSS_STATUS_SUCCESS)
        {
          if (retval == NSS_STATUS_TRYAGAIN)
            {
              __set_errno (EAGAIN);
              *herrnop = NETDB_INTERNAL;
            }
	  nis_freeresult (result);
          return retval;
        }

      parse_res = _nss_nisplus_parse_hostent (result, type, host,
					      buffer, buflen);
      nis_freeresult (result);

      if (parse_res > 0)
	return NSS_STATUS_SUCCESS;

      *herrnop = NETDB_INTERNAL;
      if (parse_res == -1)
	return NSS_STATUS_TRYAGAIN;
      else
	return NSS_STATUS_NOTFOUND;
    }
}
