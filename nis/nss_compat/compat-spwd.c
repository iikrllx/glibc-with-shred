/* Copyright (C) 1996-1999,2001,2002,2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1996.

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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <nss.h>
#include <nsswitch.h>
#include <shadow.h>
#include <stdio_ext.h>
#include <string.h>
#include <rpc/types.h>
#include <rpcsvc/ypclnt.h>
#include <bits/libc-lock.h>

#include "netgroup.h"

static service_user *ni;
static enum nss_status (*nss_setspent) (int stayopen);
static enum nss_status (*nss_getspnam_r) (const char *name, struct spwd * sp,
					  char *buffer, size_t buflen,
					  int *errnop);
static enum nss_status (*nss_getspent_r) (struct spwd * sp, char *buffer,
					  size_t buflen, int *errnop);
static enum nss_status (*nss_endspent) (void);

/* Get the declaration of the parser function.  */
#define ENTNAME spent
#define STRUCTURE spwd
#define EXTERN_PARSER
#include <nss/nss_files/files-parse.c>

/* Structure for remembering -@netgroup and -user members ... */
#define BLACKLIST_INITIAL_SIZE 512
#define BLACKLIST_INCREMENT 256
struct blacklist_t
{
  char *data;
  int current;
  int size;
};

struct ent_t
{
  bool_t netgroup;
  bool_t files;
  bool_t first;
  FILE *stream;
  struct blacklist_t blacklist;
  struct spwd pwd;
  struct __netgrent netgrdata;
};
typedef struct ent_t ent_t;

static ent_t ext_ent = {0, TRUE, 0, NULL, {NULL, 0, 0},
			{NULL, NULL, 0, 0, 0, 0, 0, 0, 0}};

/* Protect global state against multiple changers.  */
__libc_lock_define_initialized (static, lock)

/* Prototypes for local functions.  */
static void blacklist_store_name (const char *, ent_t *);
static int in_blacklist (const char *, int, ent_t *);

/* Initialize the NSS interface/functions. The calling function must
   hold the lock.  */
static void
init_nss_interface (void)
{
  if (__nss_database_lookup ("shadow_compat", "passwd_compat",
			     "nis", &ni) >= 0)
    {
      nss_setspent = __nss_lookup_function (ni, "setspent");
      nss_getspnam_r = __nss_lookup_function (ni, "getspnam_r");
      nss_getspent_r = __nss_lookup_function (ni, "getspent_r");
      nss_endspent = __nss_lookup_function (ni, "endspent");
    }
}

static void
give_spwd_free (struct spwd *pwd)
{
  if (pwd->sp_namp != NULL)
    free (pwd->sp_namp);
  if (pwd->sp_pwdp != NULL)
    free (pwd->sp_pwdp);

  memset (pwd, '\0', sizeof (struct spwd));
  pwd->sp_warn = -1;
  pwd->sp_inact = -1;
  pwd->sp_expire = -1;
  pwd->sp_flag = ~0ul;
}

static int
spwd_need_buflen (struct spwd *pwd)
{
  int len = 0;

  if (pwd->sp_pwdp != NULL)
    len += strlen (pwd->sp_pwdp) + 1;

  return len;
}

static void
copy_spwd_changes (struct spwd *dest, struct spwd *src,
		   char *buffer, size_t buflen)
{
  if (src->sp_pwdp != NULL && strlen (src->sp_pwdp))
    {
      if (buffer == NULL)
	dest->sp_pwdp = strdup (src->sp_pwdp);
      else if (dest->sp_pwdp &&
	       strlen (dest->sp_pwdp) >= strlen (src->sp_pwdp))
	strcpy (dest->sp_pwdp, src->sp_pwdp);
      else
	{
	  dest->sp_pwdp = buffer;
	  strcpy (dest->sp_pwdp, src->sp_pwdp);
	  buffer += strlen (dest->sp_pwdp) + 1;
	  buflen = buflen - (strlen (dest->sp_pwdp) + 1);
	}
    }
  if (src->sp_lstchg != 0)
    dest->sp_lstchg = src->sp_lstchg;
  if (src->sp_min != 0)
    dest->sp_min = src->sp_min;
  if (src->sp_max != 0)
    dest->sp_max = src->sp_max;
  if (src->sp_warn != -1)
    dest->sp_warn = src->sp_warn;
  if (src->sp_inact != -1)
    dest->sp_inact = src->sp_inact;
  if (src->sp_expire != -1)
    dest->sp_expire = src->sp_expire;
  if (src->sp_flag != ~0ul)
    dest->sp_flag = src->sp_flag;
}

static enum nss_status
internal_setspent (ent_t *ent, int stayopen)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  ent->first = ent->netgroup = 0;
  ent->files = TRUE;

  /* If something was left over free it.  */
  if (ent->netgroup)
    __internal_endnetgrent (&ent->netgrdata);

  if (ent->blacklist.data != NULL)
    {
      ent->blacklist.current = 1;
      ent->blacklist.data[0] = '|';
      ent->blacklist.data[1] = '\0';
    }
  else
    ent->blacklist.current = 0;

  if (ent->stream == NULL)
    {
      ent->stream = fopen ("/etc/shadow", "rm");

      if (ent->stream == NULL)
	status = errno == EAGAIN ? NSS_STATUS_TRYAGAIN : NSS_STATUS_UNAVAIL;
      else
	{
	  /* We have to make sure the file is  `closed on exec'.  */
	  int result, flags;

	  result = flags = fcntl (fileno_unlocked (ent->stream), F_GETFD, 0);
	  if (result >= 0)
	    {
	      flags |= FD_CLOEXEC;
	      result = fcntl (fileno_unlocked (ent->stream), F_SETFD, flags);
	    }
	  if (result < 0)
	    {
	      /* Something went wrong.  Close the stream and return a
	         failure.  */
	      fclose (ent->stream);
	      ent->stream = NULL;
	      status = NSS_STATUS_UNAVAIL;
	    }
	  else
	    /* We take care of locking ourself.  */
	    __fsetlocking (ent->stream, FSETLOCKING_BYCALLER);
	}
    }
  else
    rewind (ent->stream);

  give_spwd_free (&ent->pwd);

  if (status == NSS_STATUS_SUCCESS && nss_setspent)
    return nss_setspent (stayopen);

  return status;
}


enum nss_status
_nss_compat_setspent (int stayopen)
{
  enum nss_status result;

  __libc_lock_lock (lock);

  if (ni == NULL)
    init_nss_interface ();

  result = internal_setspent (&ext_ent, stayopen);

  __libc_lock_unlock (lock);

  return result;
}


static enum nss_status
internal_endspent (ent_t *ent)
{
  if (nss_endspent)
    nss_endspent ();

  if (ent->stream != NULL)
    {
      fclose (ent->stream);
      ent->stream = NULL;
    }

  if (ent->netgroup)
    __internal_endnetgrent (&ent->netgrdata);

  ent->first = ent->netgroup = FALSE;
  ent->files = TRUE;

  if (ent->blacklist.data != NULL)
    {
      ent->blacklist.current = 1;
      ent->blacklist.data[0] = '|';
      ent->blacklist.data[1] = '\0';
    }
  else
    ent->blacklist.current = 0;

  give_spwd_free (&ent->pwd);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_compat_endspent (void)
{
  enum nss_status result;

  __libc_lock_lock (lock);

  result = internal_endspent (&ext_ent);

  __libc_lock_unlock (lock);

  return result;
}


static enum nss_status
getspent_next_nss_netgr (const char *name, struct spwd *result, ent_t *ent,
			 char *group, char *buffer, size_t buflen,
			 int *errnop)
{
  char *curdomain, *host, *user, *domain, *p2;
  size_t p2len;

  if (!nss_getspnam_r)
    return NSS_STATUS_UNAVAIL;

  if (yp_get_default_domain (&curdomain) != YPERR_SUCCESS)
    {
      ent->netgroup = FALSE;
      ent->first = FALSE;
      give_spwd_free (&ent->pwd);
      return NSS_STATUS_UNAVAIL;
    }

  if (ent->first == TRUE)
    {
      memset (&ent->netgrdata, 0, sizeof (struct __netgrent));
      __internal_setnetgrent (group, &ent->netgrdata);
      ent->first = FALSE;
    }

  while (1)
    {
      char *saved_cursor;
      enum nss_status status;

      saved_cursor = ent->netgrdata.cursor;
      status = __internal_getnetgrent_r (&host, &user, &domain,
					 &ent->netgrdata, buffer, buflen,
					 errnop);
      if (status != 1)
	{
	  __internal_endnetgrent (&ent->netgrdata);
	  ent->netgroup = FALSE;
	  give_spwd_free (&ent->pwd);
	  return NSS_STATUS_RETURN;
	}

      if (user == NULL || user[0] == '-')
	continue;

      if (domain != NULL && strcmp (curdomain, domain) != 0)
	continue;

      /* If name != NULL, we are called from getpwnam */
      if (name != NULL)
	if (strcmp (user, name) != 0)
	  continue;

      p2len = spwd_need_buflen (&ent->pwd);
      if (p2len > buflen)
	{
	  *errnop = ERANGE;
	  return NSS_STATUS_TRYAGAIN;
	}
      p2 = buffer + (buflen - p2len);
      buflen -= p2len;

      if (nss_getspnam_r (user, result, buffer, buflen, errnop) !=
	  NSS_STATUS_SUCCESS)
	continue;

      if (!in_blacklist (result->sp_namp, strlen (result->sp_namp), ent))
	{
	  /* Store the User in the blacklist for possible the "+" at the
	     end of /etc/passwd */
	  blacklist_store_name (result->sp_namp, ent);
	  copy_spwd_changes (result, &ent->pwd, p2, p2len);
	  break;
	}
    }

  return NSS_STATUS_SUCCESS;
}


static enum nss_status
getspent_next_nss (struct spwd *result, ent_t *ent,
		   char *buffer, size_t buflen, int *errnop)
{
  enum nss_status status;
  char *p2;
  size_t p2len;

  if (!nss_getspent_r)
    return NSS_STATUS_UNAVAIL;

  p2len = spwd_need_buflen (&ent->pwd);
  if (p2len > buflen)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
  p2 = buffer + (buflen - p2len);
  buflen -= p2len;
  do
    {
      if ((status = nss_getspent_r (result, buffer, buflen, errnop)) !=
	  NSS_STATUS_SUCCESS)
	return status;
    }
  while (in_blacklist (result->sp_namp, strlen (result->sp_namp), ent));

  copy_spwd_changes (result, &ent->pwd, p2, p2len);

  return NSS_STATUS_SUCCESS;
}

/* This function handle the +user entrys in /etc/shadow */
static enum nss_status
getspnam_plususer (const char *name, struct spwd *result, ent_t *ent,
		   char *buffer, size_t buflen, int *errnop)
{
  struct spwd pwd;
  char *p;
  size_t plen;

  if (!nss_getspnam_r)
    return NSS_STATUS_UNAVAIL;

  memset (&pwd, '\0', sizeof (struct spwd));
  pwd.sp_warn = -1;
  pwd.sp_inact = -1;
  pwd.sp_expire = -1;
  pwd.sp_flag = ~0ul;

  copy_spwd_changes (&pwd, result, NULL, 0);

  plen = spwd_need_buflen (&pwd);
  if (plen > buflen)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
  p = buffer + (buflen - plen);
  buflen -= plen;

  if (nss_getspnam_r (name, result, buffer, buflen, errnop) !=
      NSS_STATUS_SUCCESS)
    return NSS_STATUS_NOTFOUND;

  if (in_blacklist (result->sp_namp, strlen (result->sp_namp), ent))
    return NSS_STATUS_NOTFOUND;

  copy_spwd_changes (result, &pwd, p, plen);
  give_spwd_free (&pwd);
  /* We found the entry.  */
  return NSS_STATUS_RETURN;
}

static enum nss_status
getspent_next_file (struct spwd *result, ent_t *ent,
		    char *buffer, size_t buflen, int *errnop)
{
  struct parser_data *data = (void *) buffer;
  while (1)
    {
      fpos_t pos;
      int parse_res = 0;
      char *p;

      do
	{
	  fgetpos (ent->stream, &pos);
	  buffer[buflen - 1] = '\xff';
	  p = fgets_unlocked (buffer, buflen, ent->stream);
	  if (p == NULL && feof_unlocked (ent->stream))
	    return NSS_STATUS_NOTFOUND;

	  if (p == NULL || buffer[buflen - 1] != '\xff')
	    {
	      fsetpos (ent->stream, &pos);
	      *errnop = ERANGE;
	      return NSS_STATUS_TRYAGAIN;
	    }

	  /* Skip leading blanks.  */
	  while (isspace (*p))
	    ++p;
	}
      while (*p == '\0' || *p == '#'	/* Ignore empty and comment lines.  */
	     /* Parse the line.  If it is invalid, loop to
	        get the next line of the file to parse.  */
	     || !(parse_res = _nss_files_parse_spent (p, result, data,
						      buflen, errnop)));

      if (parse_res == -1)
	{
	  /* The parser ran out of space.  */
	  fsetpos (ent->stream, &pos);
	  *errnop = ERANGE;
	  return NSS_STATUS_TRYAGAIN;
	}

      if (result->sp_namp[0] != '+' && result->sp_namp[0] != '-')
	/* This is a real entry.  */
	break;

      /* -@netgroup */
      if (result->sp_namp[0] == '-' && result->sp_namp[1] == '@'
	  && result->sp_namp[2] != '\0')
	{
	  /* XXX Do not use fixed length buffers.  */
	  char buf2[1024];
	  char *user, *host, *domain;
	  struct __netgrent netgrdata;

	  bzero (&netgrdata, sizeof (struct __netgrent));
	  __internal_setnetgrent (&result->sp_namp[2], &netgrdata);
	  while (__internal_getnetgrent_r (&host, &user, &domain,
					   &netgrdata, buf2, sizeof (buf2),
					   errnop))
	    {
	      if (user != NULL && user[0] != '-')
		blacklist_store_name (user, ent);
	    }
	  __internal_endnetgrent (&netgrdata);
	  continue;
	}

      /* +@netgroup */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] == '@'
	  && result->sp_namp[2] != '\0')
	{
	  int status;

	  ent->netgroup = TRUE;
	  ent->first = TRUE;
	  copy_spwd_changes (&ent->pwd, result, NULL, 0);

	  status = getspent_next_nss_netgr (NULL, result, ent,
					    &result->sp_namp[2],
					    buffer, buflen, errnop);
	  if (status == NSS_STATUS_RETURN)
	    continue;
	  else
	    return status;
	}

      /* -user */
      if (result->sp_namp[0] == '-' && result->sp_namp[1] != '\0'
	  && result->sp_namp[1] != '@')
	{
	  blacklist_store_name (&result->sp_namp[1], ent);
	  continue;
	}

      /* +user */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] != '\0'
	  && result->sp_namp[1] != '@')
	{
	  enum nss_status status;

	  /* Store the User in the blacklist for the "+" at the end of
	     /etc/passwd */
	  blacklist_store_name (&result->sp_namp[1], ent);
	  status = getspnam_plususer (&result->sp_namp[1], result, ent,
				      buffer, buflen, errnop);

	  if (status == NSS_STATUS_SUCCESS)	/* We found the entry. */
	    break;
	  else if (status == NSS_STATUS_RETURN	/* We couldn't parse the entry */
		   || status == NSS_STATUS_NOTFOUND)	/* entry doesn't exist */
	    continue;
	  else
	    {
	      if (status == NSS_STATUS_TRYAGAIN)
		{
		  fsetpos (ent->stream, &pos);
		  *errnop = ERANGE;
		}
	      return status;
	    }
	}

      /* +:... */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] == '\0')
	{
	  ent->files = FALSE;
	  ent->first = TRUE;
	  copy_spwd_changes (&ent->pwd, result, NULL, 0);

	  return getspent_next_nss (result, ent, buffer, buflen, errnop);
	}
    }

  return NSS_STATUS_SUCCESS;
}


static enum nss_status
internal_getspent_r (struct spwd *pw, ent_t *ent,
		     char *buffer, size_t buflen, int *errnop)
{
  if (ent->netgroup)
    {
      enum nss_status status;

      /* We are searching members in a netgroup */
      /* Since this is not the first call, we don't need the group name */
      status = getspent_next_nss_netgr (NULL, pw, ent, NULL, buffer,
					buflen, errnop);

      if (status == NSS_STATUS_RETURN)
	return getspent_next_file (pw, ent, buffer, buflen, errnop);
      else
	return status;
    }
  else if (ent->files)
    return getspent_next_file (pw, ent, buffer, buflen, errnop);
  else
    return getspent_next_nss (pw, ent, buffer, buflen, errnop);
}

enum nss_status
_nss_compat_getspent_r (struct spwd *pwd, char *buffer, size_t buflen,
			int *errnop)
{
  enum nss_status result = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  /* Be prepared that the setpwent function was not called before.  */
  if (ni == NULL)
    init_nss_interface ();

  if (ext_ent.stream == NULL)
    result = internal_setspent (&ext_ent, 1);

  if (result == NSS_STATUS_SUCCESS)
    result = internal_getspent_r (pwd, &ext_ent, buffer, buflen, errnop);

  __libc_lock_unlock (lock);

  return result;
}

/* Searches in /etc/passwd and the NIS/NIS+ map for a special user */
static enum nss_status
internal_getspnam_r (const char *name, struct spwd *result, ent_t *ent,
		     char *buffer, size_t buflen, int *errnop)
{
  struct parser_data *data = (void *) buffer;

  while (1)
    {
      fpos_t pos;
      char *p;
      int parse_res;

      do
	{
	  fgetpos (ent->stream, &pos);
	  buffer[buflen - 1] = '\xff';
	  p = fgets_unlocked (buffer, buflen, ent->stream);
	  if (p == NULL && feof_unlocked (ent->stream))
	    return NSS_STATUS_NOTFOUND;

	  if (p == NULL || buffer[buflen - 1] != '\xff')
	    {
	      fsetpos (ent->stream, &pos);
	      *errnop = ERANGE;
	      return NSS_STATUS_TRYAGAIN;
	    }

	  /* Skip leading blanks.  */
	  while (isspace (*p))
	    ++p;
	}
      while (*p == '\0' || *p == '#' ||	/* Ignore empty and comment lines.  */
	     /* Parse the line.  If it is invalid, loop to
	        get the next line of the file to parse.  */
	     !(parse_res = _nss_files_parse_spent (p, result, data, buflen,
						   errnop)));

      if (parse_res == -1)
	{
	  /* The parser ran out of space.  */
	  fsetpos (ent->stream, &pos);
	  *errnop = ERANGE;
	  return NSS_STATUS_TRYAGAIN;
	}

      /* This is a real entry.  */
      if (result->sp_namp[0] != '+' && result->sp_namp[0] != '-')
	{
	  if (strcmp (result->sp_namp, name) == 0)
	    return NSS_STATUS_SUCCESS;
	  else
	    continue;
	}

      /* -@netgroup */
      /* If the loaded NSS module does not support this service, add
         all users from a +@netgroup entry to the blacklist, too.  */
      if (result->sp_namp[0] == '-' && result->sp_namp[1] == '@'
	  && result->sp_namp[2] != '\0')
	{
	  /* XXX Do not use fixed length buffers.  */
	  char buf2[1024];
	  char *user, *host, *domain;
	  struct __netgrent netgrdata;

	  bzero (&netgrdata, sizeof (struct __netgrent));
	  __internal_setnetgrent (&result->sp_namp[2], &netgrdata);
	  while (__internal_getnetgrent_r (&host, &user, &domain, &netgrdata,
					   buf2, sizeof (buf2), errnop))
	    {
	      if (user != NULL && user[0] != '-')
		if (strcmp (user, name) == 0)
		  return NSS_STATUS_NOTFOUND;
	    }
	  __internal_endnetgrent (&netgrdata);
	  continue;
	}

      /* +@netgroup */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] == '@'
	  && result->sp_namp[2] != '\0')
	{
	  char *buf = strdupa (&result->sp_namp[2]);
	  int status;

	  ent->netgroup = TRUE;
	  ent->first = TRUE;
	  copy_spwd_changes (&ent->pwd, result, NULL, 0);

	  do
	    {
	      status = getspent_next_nss_netgr (name, result, ent, buf,
						buffer, buflen, errnop);
	      if (status == NSS_STATUS_RETURN)
		continue;

	      if (status == NSS_STATUS_SUCCESS
		  && strcmp (result->sp_namp, name) == 0)
		return NSS_STATUS_SUCCESS;
	    }
	  while (status == NSS_STATUS_SUCCESS);
	  continue;
	}

      /* -user */
      if (result->sp_namp[0] == '-' && result->sp_namp[1] != '\0'
	  && result->sp_namp[1] != '@')
	{
	  if (strcmp (&result->sp_namp[1], name) == 0)
	    return NSS_STATUS_NOTFOUND;
	  else
	    continue;
	}

      /* +user */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] != '\0'
	  && result->sp_namp[1] != '@')
	{
	  if (strcmp (name, &result->sp_namp[1]) == 0)
	    {
	      enum nss_status status;

	      status = getspnam_plususer (name, result, ent,
					  buffer, buflen, errnop);

	      if (status == NSS_STATUS_RETURN)
		/* We couldn't parse the entry */
		return NSS_STATUS_NOTFOUND;
	      else
		return status;
	    }
	}

      /* +:... */
      if (result->sp_namp[0] == '+' && result->sp_namp[1] == '\0')
	{
	  enum nss_status status;

	  status = getspnam_plususer (name, result, ent,
				      buffer, buflen, errnop);

	  if (status == NSS_STATUS_RETURN)	/* We couldn't parse the entry */
	    return NSS_STATUS_NOTFOUND;
	  else
	    return status;
	}
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_compat_getspnam_r (const char *name, struct spwd *pwd,
			char *buffer, size_t buflen, int *errnop)
{
  enum nss_status result;
  ent_t ent = {0, TRUE, 0, NULL, {NULL, 0, 0},
	       {NULL, NULL, 0, 0, 0, 0, 0, 0, 0}};

  if (name[0] == '-' || name[0] == '+')
    return NSS_STATUS_NOTFOUND;

  __libc_lock_lock (lock);

  if (ni == NULL)
    init_nss_interface ();

  __libc_lock_unlock (lock);

  result = internal_setspent (&ent, 0);

  if (result != NSS_STATUS_SUCCESS)
    return result;

  result = internal_getspnam_r (name, pwd, &ent, buffer, buflen, errnop);

  internal_endspent (&ent);

  return result;
}

/* Support routines for remembering -@netgroup and -user entries.
   The names are stored in a single string with `|' as separator. */
static void
blacklist_store_name (const char *name, ent_t *ent)
{
  int namelen = strlen (name);
  char *tmp;

  /* first call, setup cache */
  if (ent->blacklist.size == 0)
    {
      ent->blacklist.size = MAX (BLACKLIST_INITIAL_SIZE, 2 * namelen);
      ent->blacklist.data = malloc (ent->blacklist.size);
      if (ent->blacklist.data == NULL)
	return;
      ent->blacklist.data[0] = '|';
      ent->blacklist.data[1] = '\0';
      ent->blacklist.current = 1;
    }
  else
    {
      if (in_blacklist (name, namelen, ent))
	return;			/* no duplicates */

      if (ent->blacklist.current + namelen + 1 >= ent->blacklist.size)
	{
	  ent->blacklist.size += MAX (BLACKLIST_INCREMENT, 2 * namelen);
	  tmp = realloc (ent->blacklist.data, ent->blacklist.size);
	  if (tmp == NULL)
	    {
	      free (ent->blacklist.data);
	      ent->blacklist.size = 0;
	      return;
	    }
	  ent->blacklist.data = tmp;
	}
    }

  tmp = stpcpy (ent->blacklist.data + ent->blacklist.current, name);
  *tmp++ = '|';
  *tmp = '\0';
  ent->blacklist.current += namelen + 1;

  return;
}

/* Returns TRUE if ent->blacklist contains name, else FALSE.  */
static bool_t
in_blacklist (const char *name, int namelen, ent_t *ent)
{
  char buf[namelen + 3];
  char *cp;

  if (ent->blacklist.data == NULL)
    return FALSE;

  buf[0] = '|';
  cp = stpcpy (&buf[1], name);
  *cp++ = '|';
  *cp = '\0';
  return strstr (ent->blacklist.data, buf) != NULL;
}
