/* Copyright (C) 1997, 2001, 2002, 2003, 2005, 2006
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1997.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <atomic.h>
#include <nss.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <bits/libc-lock.h>
#include <rpcsvc/nis.h>

#include "nss-nisplus.h"
#include "nisplus-parser.h"


__libc_lock_define_initialized (static, lock);

static nis_result *result;
static unsigned long next_entry;
static nis_name tablename_val;
static size_t tablename_len;

static enum nss_status
_nss_create_tablename (int *errnop)
{
  if (tablename_val == NULL)
    {
      const char *local_dir = nis_local_directory ();
      size_t local_dir_len = strlen (local_dir);
      static const char prefix[] = "group.org_dir.";

      char *p = malloc (sizeof (prefix) + local_dir_len);
      if (p == NULL)
	{
	  *errnop = errno;
	  return NSS_STATUS_TRYAGAIN;
	}

      memcpy (__stpcpy (p, prefix), local_dir, local_dir_len + 1);

      tablename_len = sizeof (prefix) - 1 + local_dir_len;

      atomic_write_barrier ();

      tablename_val = p;
    }

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_setgrent (void)
{
  enum nss_status status;

  if (result != NULL)
    {
      nis_freeresult (result);
      result = NULL;
    }
  next_entry = 0;

  if (tablename_val == NULL)
    {
      int err;
      if (_nss_create_tablename (&err) != NSS_STATUS_SUCCESS)
	return NSS_STATUS_UNAVAIL;
    }

  result = nis_list (tablename_val, FOLLOW_LINKS | FOLLOW_PATH, NULL, NULL);
  if (result == NULL)
    {
      status = NSS_STATUS_TRYAGAIN;
      __set_errno (ENOMEM);
    }
  else
    {
      status = niserr2nss (result->status);
      if (status != NSS_STATUS_SUCCESS)
	{
	  nis_freeresult (result);
	  result = NULL;
	}
    }
  return status;
}

enum nss_status
_nss_nisplus_setgrent (int stayopen)
{
  enum nss_status status;

  __libc_lock_lock (lock);

  status = internal_setgrent ();

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_endgrent (void)
{
  __libc_lock_lock (lock);

  if (result != NULL)
    {
      nis_freeresult (result);
      result = NULL;
    }

  __libc_lock_unlock (lock);

  return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_nisplus_getgrent_r (struct group *gr, char *buffer, size_t buflen,
			     int *errnop)
{
  int parse_res;

  if (result == NULL)
    {
      enum nss_status status;

      status = internal_setgrent ();
      if (result == NULL || status != NSS_STATUS_SUCCESS)
	return status;
    }

  /* Get the next entry until we found a correct one. */
  do
    {
      if (next_entry >= result->objects.objects_len)
	return NSS_STATUS_NOTFOUND;

      parse_res = _nss_nisplus_parse_grent (result, next_entry, gr,
					    buffer, buflen, errnop);
      if (parse_res == -1)
	return NSS_STATUS_TRYAGAIN;

      ++next_entry;
    }
  while (!parse_res);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_getgrent_r (struct group *result, char *buffer, size_t buflen,
			 int *errnop)
{
  int status;

  __libc_lock_lock (lock);

  status = internal_nisplus_getgrent_r (result, buffer, buflen, errnop);

  __libc_lock_unlock (lock);

  return status;
}

enum nss_status
_nss_nisplus_getgrnam_r (const char *name, struct group *gr,
			 char *buffer, size_t buflen, int *errnop)
{
  int parse_res;

  if (tablename_val == NULL)
    {
      __libc_lock_lock (lock);

      enum nss_status status = _nss_create_tablename (errnop);

      __libc_lock_unlock (lock);

      if (status != NSS_STATUS_SUCCESS)
	return status;
    }

  if (name == NULL)
    {
      *errnop = EINVAL;
      return NSS_STATUS_NOTFOUND;
    }

  nis_result *result;
  char buf[strlen (name) + 9 + tablename_len];
  int olderr = errno;

  snprintf (buf, sizeof (buf), "[name=%s],%s", name, tablename_val);

  result = nis_list (buf, FOLLOW_LINKS | FOLLOW_PATH, NULL, NULL);

  if (result == NULL)
    {
      *errnop = ENOMEM;
      return NSS_STATUS_TRYAGAIN;
    }

  if (__builtin_expect (niserr2nss (result->status) != NSS_STATUS_SUCCESS, 0))
    {
      enum nss_status status = niserr2nss (result->status);

      nis_freeresult (result);
      return status;
    }

  parse_res = _nss_nisplus_parse_grent (result, 0, gr, buffer, buflen, errnop);
  nis_freeresult (result);
  if (__builtin_expect (parse_res < 1, 0))
    {
      if (parse_res == -1)
	{
	  *errnop = ERANGE;
	  return NSS_STATUS_TRYAGAIN;
	}
      else
	{
	  __set_errno (olderr);
	  return NSS_STATUS_NOTFOUND;
	}
    }

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_nisplus_getgrgid_r (const gid_t gid, struct group *gr,
			 char *buffer, size_t buflen, int *errnop)
{
  if (tablename_val == NULL)
    {
      __libc_lock_lock (lock);

      enum nss_status status = _nss_create_tablename (errnop);

      __libc_lock_unlock (lock);

      if (status != NSS_STATUS_SUCCESS)
	return status;
    }

  int parse_res;
  nis_result *result;
  char buf[8 + 3 * sizeof (unsigned long int) + tablename_len];
  int olderr = errno;

  snprintf (buf, sizeof (buf), "[gid=%lu],%s",
	    (unsigned long int) gid, tablename_val);

  result = nis_list (buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);

  if (result == NULL)
    {
      *errnop = ENOMEM;
      return NSS_STATUS_TRYAGAIN;
    }

  if (__builtin_expect (niserr2nss (result->status) != NSS_STATUS_SUCCESS, 0))
    {
      enum nss_status status = niserr2nss (result->status);

      __set_errno (olderr);

      nis_freeresult (result);
      return status;
    }

  parse_res = _nss_nisplus_parse_grent (result, 0, gr, buffer, buflen, errnop);

  nis_freeresult (result);
  if (__builtin_expect (parse_res < 1, 0))
    {
      __set_errno (olderr);

      if (parse_res == -1)
	{
	  *errnop = ERANGE;
	  return NSS_STATUS_TRYAGAIN;
	}
      else
	return NSS_STATUS_NOTFOUND;
    }

  return NSS_STATUS_SUCCESS;
}
