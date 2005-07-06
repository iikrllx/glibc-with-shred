/* Copyright (C) 1996-1999,2001-2004,2005 Free Software Foundation, Inc.
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
#include <pwd.h>
#include <stdio_ext.h>
#include <string.h>
#include <rpc/types.h>
#include <rpcsvc/ypclnt.h>
#include <bits/libc-lock.h>

#include "netgroup.h"

static service_user *ni;
static enum nss_status (*nss_setpwent) (int stayopen);
static enum nss_status (*nss_getpwnam_r) (const char *name,
					  struct passwd * pwd, char *buffer,
					  size_t buflen, int *errnop);
static enum nss_status (*nss_getpwuid_r) (uid_t uid, struct passwd * pwd,
					  char *buffer, size_t buflen,
					  int *errnop);
static enum nss_status (*nss_getpwent_r) (struct passwd * pwd, char *buffer,
					  size_t buflen, int *errnop);
static enum nss_status (*nss_endpwent) (void);

/* Get the declaration of the parser function.  */
#define ENTNAME pwent
#define STRUCTURE passwd
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
  bool_t first;
  bool_t files;
  FILE *stream;
  struct blacklist_t blacklist;
  struct passwd pwd;
  struct __netgrent netgrdata;
};
typedef struct ent_t ent_t;

static ent_t ext_ent = {0, 0, TRUE, NULL, {NULL, 0, 0},
                        {NULL, NULL, 0, 0, NULL, NULL, NULL}};

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
  if (__nss_database_lookup ("passwd_compat", NULL, "nis", &ni) >= 0)
    {
      nss_setpwent = __nss_lookup_function (ni, "setpwent");
      nss_getpwnam_r = __nss_lookup_function (ni, "getpwnam_r");
      nss_getpwuid_r = __nss_lookup_function (ni, "getpwuid_r");
      nss_getpwent_r = __nss_lookup_function (ni, "getpwent_r");
      nss_endpwent = __nss_lookup_function (ni, "endpwent");
    }
}

static void
give_pwd_free (struct passwd *pwd)
{
  if (pwd->pw_name != NULL)
    free (pwd->pw_name);
  if (pwd->pw_passwd != NULL)
    free (pwd->pw_passwd);
  if (pwd->pw_gecos != NULL)
    free (pwd->pw_gecos);
  if (pwd->pw_dir != NULL)
    free (pwd->pw_dir);
  if (pwd->pw_shell != NULL)
    free (pwd->pw_shell);

  memset (pwd, '\0', sizeof (struct passwd));
}

static size_t
pwd_need_buflen (struct passwd *pwd)
{
  size_t len = 0;

  if (pwd->pw_passwd != NULL)
    len += strlen (pwd->pw_passwd) + 1;

  if (pwd->pw_gecos != NULL)
    len += strlen (pwd->pw_gecos) + 1;

  if (pwd->pw_dir != NULL)
    len += strlen (pwd->pw_dir) + 1;

  if (pwd->pw_shell != NULL)
    len += strlen (pwd->pw_shell) + 1;

  return len;
}

static void
copy_pwd_changes (struct passwd *dest, struct passwd *src,
		  char *buffer, size_t buflen)
{
  if (src->pw_passwd != NULL && strlen (src->pw_passwd))
    {
      if (buffer == NULL)
	dest->pw_passwd = strdup (src->pw_passwd);
      else if (dest->pw_passwd &&
	       strlen (dest->pw_passwd) >= strlen (src->pw_passwd))
	strcpy (dest->pw_passwd, src->pw_passwd);
      else
	{
	  dest->pw_passwd = buffer;
	  strcpy (dest->pw_passwd, src->pw_passwd);
	  buffer += strlen (dest->pw_passwd) + 1;
	  buflen = buflen - (strlen (dest->pw_passwd) + 1);
	}
    }

  if (src->pw_gecos != NULL && strlen (src->pw_gecos))
    {
      if (buffer == NULL)
	dest->pw_gecos = strdup (src->pw_gecos);
      else if (dest->pw_gecos &&
	       strlen (dest->pw_gecos) >= strlen (src->pw_gecos))
	strcpy (dest->pw_gecos, src->pw_gecos);
      else
	{
	  dest->pw_gecos = buffer;
	  strcpy (dest->pw_gecos, src->pw_gecos);
	  buffer += strlen (dest->pw_gecos) + 1;
	  buflen = buflen - (strlen (dest->pw_gecos) + 1);
	}
    }
  if (src->pw_dir != NULL && strlen (src->pw_dir))
    {
      if (buffer == NULL)
	dest->pw_dir = strdup (src->pw_dir);
      else if (dest->pw_dir && strlen (dest->pw_dir) >= strlen (src->pw_dir))
	strcpy (dest->pw_dir, src->pw_dir);
      else
	{
	  dest->pw_dir = buffer;
	  strcpy (dest->pw_dir, src->pw_dir);
	  buffer += strlen (dest->pw_dir) + 1;
	  buflen = buflen - (strlen (dest->pw_dir) + 1);
	}
    }

  if (src->pw_shell != NULL && strlen (src->pw_shell))
    {
      if (buffer == NULL)
	dest->pw_shell = strdup (src->pw_shell);
      else if (dest->pw_shell &&
	       strlen (dest->pw_shell) >= strlen (src->pw_shell))
	strcpy (dest->pw_shell, src->pw_shell);
      else
	{
	  dest->pw_shell = buffer;
	  strcpy (dest->pw_shell, src->pw_shell);
	  buffer += strlen (dest->pw_shell) + 1;
	  buflen = buflen - (strlen (dest->pw_shell) + 1);
	}
    }
}

static enum nss_status
internal_setpwent (ent_t *ent, int stayopen)
{
  enum nss_status status = NSS_STATUS_SUCCESS;

  ent->first = ent->netgroup = FALSE;
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
      ent->stream = fopen ("/etc/passwd", "rm");

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

  give_pwd_free (&ent->pwd);

  if (status == NSS_STATUS_SUCCESS && nss_setpwent)
    return nss_setpwent (stayopen);

  return status;
}


enum nss_status
_nss_compat_setpwent (int stayopen)
{
  enum nss_status result;

  __libc_lock_lock (lock);

  if (ni == NULL)
    init_nss_interface ();

  result = internal_setpwent (&ext_ent, stayopen);

  __libc_lock_unlock (lock);

  return result;
}


static enum nss_status
internal_endpwent (ent_t *ent)
{
  if (nss_endpwent)
    nss_endpwent ();

  if (ent->stream != NULL)
    {
      fclose (ent->stream);
      ent->stream = NULL;
    }

  if (ent->netgroup)
    __internal_endnetgrent (&ent->netgrdata);

  ent->first = ent->netgroup = FALSE;

  if (ent->blacklist.data != NULL)
    {
      ent->blacklist.current = 1;
      ent->blacklist.data[0] = '|';
      ent->blacklist.data[1] = '\0';
    }
  else
    ent->blacklist.current = 0;

  give_pwd_free (&ent->pwd);

  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_compat_endpwent (void)
{
  enum nss_status result;

  __libc_lock_lock (lock);

  result = internal_endpwent (&ext_ent);

  __libc_lock_unlock (lock);

  return result;
}


static enum nss_status
getpwent_next_nss_netgr (const char *name, struct passwd *result, ent_t *ent,
			 char *group, char *buffer, size_t buflen,
			 int *errnop)
{
  char *curdomain, *host, *user, *domain, *p2;
  int status;
  size_t p2len;

  /* Leave function if NSS module does not support getpwnam_r,
     we need this function here.  */
  if (!nss_getpwnam_r)
    return NSS_STATUS_UNAVAIL;

  if (yp_get_default_domain (&curdomain) != YPERR_SUCCESS)
    {
      ent->netgroup = FALSE;
      ent->first = FALSE;
      give_pwd_free (&ent->pwd);
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

      saved_cursor = ent->netgrdata.cursor;
      status = __internal_getnetgrent_r (&host, &user, &domain,
					 &ent->netgrdata, buffer, buflen,
					 errnop);
      if (status != 1)
	{
	  __internal_endnetgrent (&ent->netgrdata);
	  ent->netgroup = 0;
	  give_pwd_free (&ent->pwd);
	  return NSS_STATUS_RETURN;
	}

      if (user == NULL || user[0] == '-')
	continue;

      if (domain != NULL && strcmp (curdomain, domain) != 0)
	continue;

      /* If name != NULL, we are called from getpwnam.  */
      if (name != NULL)
	if (strcmp (user, name) != 0)
	  continue;

      p2len = pwd_need_buflen (&ent->pwd);
      if (p2len > buflen)
	{
	  *errnop = ERANGE;
	  return NSS_STATUS_TRYAGAIN;
	}
      p2 = buffer + (buflen - p2len);
      buflen -= p2len;

      if (nss_getpwnam_r (user, result, buffer, buflen, errnop) !=
	  NSS_STATUS_SUCCESS)
	continue;

      if (!in_blacklist (result->pw_name, strlen (result->pw_name), ent))
	{
	  /* Store the User in the blacklist for possible the "+" at the
	     end of /etc/passwd */
	  blacklist_store_name (result->pw_name, ent);
	  copy_pwd_changes (result, &ent->pwd, p2, p2len);
	  break;
	}
    }

  return NSS_STATUS_SUCCESS;
}

/* get the next user from NSS  (+ entry) */
static enum nss_status
getpwent_next_nss (struct passwd *result, ent_t *ent, char *buffer,
		   size_t buflen, int *errnop)
{
  enum nss_status status;
  char *p2;
  size_t p2len;

  /* Return if NSS module does not support getpwent_r.  */
  if (!nss_getpwent_r)
    return NSS_STATUS_UNAVAIL;

  p2len = pwd_need_buflen (&ent->pwd);
  if (p2len > buflen)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
  p2 = buffer + (buflen - p2len);
  buflen -= p2len;

  if (ent->first)
    ent->first = FALSE;

  do
    {
      if ((status = nss_getpwent_r (result, buffer, buflen, errnop)) !=
	  NSS_STATUS_SUCCESS)
	return status;
    }
  while (in_blacklist (result->pw_name, strlen (result->pw_name), ent));

  copy_pwd_changes (result, &ent->pwd, p2, p2len);

  return NSS_STATUS_SUCCESS;
}

/* This function handle the +user entrys in /etc/passwd */
static enum nss_status
getpwnam_plususer (const char *name, struct passwd *result, ent_t *ent,
		   char *buffer, size_t buflen, int *errnop)
{
  if (!nss_getpwnam_r)
    return NSS_STATUS_UNAVAIL;

  struct passwd pwd;
  memset (&pwd, '\0', sizeof (struct passwd));

  copy_pwd_changes (&pwd, result, NULL, 0);

  size_t plen = pwd_need_buflen (&pwd);
  if (plen > buflen)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
  char *p = buffer + (buflen - plen);
  buflen -= plen;

  enum nss_status status = nss_getpwnam_r (name, result, buffer, buflen,
					   errnop);
  if (status != NSS_STATUS_SUCCESS)
    return status;

  if (in_blacklist (result->pw_name, strlen (result->pw_name), ent))
    return NSS_STATUS_NOTFOUND;

  copy_pwd_changes (result, &pwd, p, plen);
  give_pwd_free (&pwd);
  /* We found the entry.  */
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
getpwent_next_file (struct passwd *result, ent_t *ent,
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
	  /* We need at least 3 characters for one line.  */
	  if (__builtin_expect (buflen < 3, 0))
	    {
	    erange:
	      *errnop = ERANGE;
	      return NSS_STATUS_TRYAGAIN;
	    }

	  fgetpos (ent->stream, &pos);
	  buffer[buflen - 1] = '\xff';
	  p = fgets_unlocked (buffer, buflen, ent->stream);
	  if (p == NULL && feof_unlocked (ent->stream))
	    return NSS_STATUS_NOTFOUND;

	  if (p == NULL || __builtin_expect (buffer[buflen - 1] != '\xff', 0))
	    {
	    erange_reset:
	      fsetpos (ent->stream, &pos);
	      goto erange;
	    }

	  /* Terminate the line for any case.  */
	  buffer[buflen - 1] = '\0';

	  /* Skip leading blanks.  */
	  while (isspace (*p))
	    ++p;
	}
      while (*p == '\0' || *p == '#' ||	/* Ignore empty and comment lines.  */
	     /* Parse the line.  If it is invalid, loop to
	        get the next line of the file to parse.  */
	     !(parse_res = _nss_files_parse_pwent (p, result, data, buflen,
						   errnop)));

      if (__builtin_expect (parse_res == -1, 0))
	/* The parser ran out of space.  */
	goto erange_reset;

      if (result->pw_name[0] != '+' && result->pw_name[0] != '-')
	/* This is a real entry.  */
	break;

      /* -@netgroup */
      if (result->pw_name[0] == '-' && result->pw_name[1] == '@'
	  && result->pw_name[2] != '\0')
	{
	  /* XXX Do not use fixed length buffer.  */
	  char buf2[1024];
	  char *user, *host, *domain;
	  struct __netgrent netgrdata;

	  bzero (&netgrdata, sizeof (struct __netgrent));
	  __internal_setnetgrent (&result->pw_name[2], &netgrdata);
	  while (__internal_getnetgrent_r (&host, &user, &domain, &netgrdata,
					   buf2, sizeof (buf2), errnop))
	    {
	      if (user != NULL && user[0] != '-')
		blacklist_store_name (user, ent);
	    }
	  __internal_endnetgrent (&netgrdata);
	  continue;
	}

      /* +@netgroup */
      if (result->pw_name[0] == '+' && result->pw_name[1] == '@'
	  && result->pw_name[2] != '\0')
	{
	  enum nss_status status;

	  ent->netgroup = TRUE;
	  ent->first = TRUE;
	  copy_pwd_changes (&ent->pwd, result, NULL, 0);

	  status = getpwent_next_nss_netgr (NULL, result, ent,
					    &result->pw_name[2],
					    buffer, buflen, errnop);
	  if (status == NSS_STATUS_RETURN)
	    continue;
	  else
	    return status;
	}

      /* -user */
      if (result->pw_name[0] == '-' && result->pw_name[1] != '\0'
	  && result->pw_name[1] != '@')
	{
	  blacklist_store_name (&result->pw_name[1], ent);
	  continue;
	}

      /* +user */
      if (result->pw_name[0] == '+' && result->pw_name[1] != '\0'
	  && result->pw_name[1] != '@')
	{
	  size_t len = strlen (result->pw_name);
	  char buf[len];
	  enum nss_status status;

	  /* Store the User in the blacklist for the "+" at the end of
	     /etc/passwd */
	  memcpy (buf, &result->pw_name[1], len);
	  status = getpwnam_plususer (&result->pw_name[1], result, ent,
				      buffer, buflen, errnop);
	  blacklist_store_name (buf, ent);

	  if (status == NSS_STATUS_SUCCESS)	/* We found the entry. */
	    break;
	  else if (status == NSS_STATUS_RETURN	/* We couldn't parse the entry */
		   || status == NSS_STATUS_NOTFOUND)	/* entry doesn't exist */
	    continue;
	  else
	    {
	      if (status == NSS_STATUS_TRYAGAIN)
		{
		  /* The parser ran out of space */
		  fsetpos (ent->stream, &pos);
		  *errnop = ERANGE;
		}
	      return status;
	    }
	}

      /* +:... */
      if (result->pw_name[0] == '+' && result->pw_name[1] == '\0')
	{
	  ent->files = FALSE;
	  ent->first = TRUE;
	  copy_pwd_changes (&ent->pwd, result, NULL, 0);

	  return getpwent_next_nss (result, ent, buffer, buflen, errnop);
	}
    }

  return NSS_STATUS_SUCCESS;
}


static enum nss_status
internal_getpwent_r (struct passwd *pw, ent_t *ent, char *buffer,
		     size_t buflen, int *errnop)
{
  if (ent->netgroup)
    {
      enum nss_status status;

      /* We are searching members in a netgroup */
      /* Since this is not the first call, we don't need the group name */
      status = getpwent_next_nss_netgr (NULL, pw, ent, NULL, buffer, buflen,
					errnop);
      if (status == NSS_STATUS_RETURN)
	return getpwent_next_file (pw, ent, buffer, buflen, errnop);
      else
	return status;
    }
  else if (ent->files)
    return getpwent_next_file (pw, ent, buffer, buflen, errnop);
  else
    return getpwent_next_nss (pw, ent, buffer, buflen, errnop);

}

enum nss_status
_nss_compat_getpwent_r (struct passwd *pwd, char *buffer, size_t buflen,
			int *errnop)
{
  enum nss_status result = NSS_STATUS_SUCCESS;

  __libc_lock_lock (lock);

  /* Be prepared that the setpwent function was not called before.  */
  if (ni == NULL)
    init_nss_interface ();

  if (ext_ent.stream == NULL)
    result = internal_setpwent (&ext_ent, 1);

  if (result == NSS_STATUS_SUCCESS)
    result = internal_getpwent_r (pwd, &ext_ent, buffer, buflen, errnop);

  __libc_lock_unlock (lock);

  return result;
}

/* Searches in /etc/passwd and the NIS/NIS+ map for a special user */
static enum nss_status
internal_getpwnam_r (const char *name, struct passwd *result, ent_t *ent,
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
	  /* We need at least 3 characters for one line.  */
	  if (__builtin_expect (buflen < 3, 0))
	    {
	    erange:
	      *errnop = ERANGE;
	      return NSS_STATUS_TRYAGAIN;
	    }

	  fgetpos (ent->stream, &pos);
	  buffer[buflen - 1] = '\xff';
	  p = fgets_unlocked (buffer, buflen, ent->stream);
	  if (p == NULL && feof_unlocked (ent->stream))
	    {
	      return NSS_STATUS_NOTFOUND;
	    }
	  if (p == NULL || __builtin_expect (buffer[buflen - 1] != '\xff', 0))
	    {
	    erange_reset:
	      fsetpos (ent->stream, &pos);
	      goto erange;
	    }

	  /* Terminate the line for any case.  */
	  buffer[buflen - 1] = '\0';

	  /* Skip leading blanks.  */
	  while (isspace (*p))
	    ++p;
	}
      while (*p == '\0' || *p == '#' ||	/* Ignore empty and comment lines.  */
	     /* Parse the line.  If it is invalid, loop to
	        get the next line of the file to parse.  */
	     !(parse_res = _nss_files_parse_pwent (p, result, data, buflen,
						   errnop)));

      if (__builtin_expect (parse_res == -1, 0))
	/* The parser ran out of space.  */
	goto erange_reset;

      /* This is a real entry.  */
      if (result->pw_name[0] != '+' && result->pw_name[0] != '-')
	{
	  if (strcmp (result->pw_name, name) == 0)
	    return NSS_STATUS_SUCCESS;
	  else
	    continue;
	}

      /* -@netgroup */
      if (result->pw_name[0] == '-' && result->pw_name[1] == '@'
	  && result->pw_name[2] != '\0')
	{
	  if (innetgr (&result->pw_name[2], NULL, name, NULL))
	    return NSS_STATUS_NOTFOUND;
	  continue;
	}

      /* +@netgroup */
      if (result->pw_name[0] == '+' && result->pw_name[1] == '@'
	  && result->pw_name[2] != '\0')
	{
	  enum nss_status status;

	  if (innetgr (&result->pw_name[2], NULL, name, NULL))
	    {
	      status = getpwnam_plususer (name, result, ent, buffer,
					  buflen, errnop);

	      if (status == NSS_STATUS_RETURN)
		continue;

	      return status;
	    }
	  continue;
	}

      /* -user */
      if (result->pw_name[0] == '-' && result->pw_name[1] != '\0'
	  && result->pw_name[1] != '@')
	{
	  if (strcmp (&result->pw_name[1], name) == 0)
	    return NSS_STATUS_NOTFOUND;
	  else
	    continue;
	}

      /* +user */
      if (result->pw_name[0] == '+' && result->pw_name[1] != '\0'
	  && result->pw_name[1] != '@')
	{
	  if (strcmp (name, &result->pw_name[1]) == 0)
	    {
	      enum nss_status status;

	      status = getpwnam_plususer (name, result, ent, buffer, buflen,
					  errnop);
	      if (status == NSS_STATUS_RETURN)
		/* We couldn't parse the entry */
		return NSS_STATUS_NOTFOUND;
	      else
		return status;
	    }
	}

      /* +:... */
      if (result->pw_name[0] == '+' && result->pw_name[1] == '\0')
	{
	  enum nss_status status;

	  status = getpwnam_plususer (name, result, ent,
				      buffer, buflen, errnop);
	  if (status == NSS_STATUS_SUCCESS)	/* We found the entry. */
	    break;
	  else if (status == NSS_STATUS_RETURN)	/* We couldn't parse the entry */
	    return NSS_STATUS_NOTFOUND;
	  else
	    return status;
	}
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_compat_getpwnam_r (const char *name, struct passwd *pwd,
			char *buffer, size_t buflen, int *errnop)
{
  enum nss_status result;
  ent_t ent = {0, 0, TRUE, NULL, {NULL, 0, 0},
               {NULL, NULL, 0, 0, NULL, NULL, NULL}};

  if (name[0] == '-' || name[0] == '+')
    return NSS_STATUS_NOTFOUND;

  __libc_lock_lock (lock);

  if (ni == NULL)
    init_nss_interface ();

  __libc_lock_unlock (lock);

  result = internal_setpwent (&ent, 0);

  if (result == NSS_STATUS_SUCCESS)
    result = internal_getpwnam_r (name, pwd, &ent, buffer, buflen, errnop);

  internal_endpwent (&ent);

  return result;
}

/* This function handle the + entry in /etc/passwd for getpwuid */
static enum nss_status
getpwuid_plususer (uid_t uid, struct passwd *result, char *buffer,
		   size_t buflen, int *errnop)
{
  struct passwd pwd;
  char *p;
  size_t plen;

  if (!nss_getpwuid_r)
    return NSS_STATUS_UNAVAIL;

  memset (&pwd, '\0', sizeof (struct passwd));

  copy_pwd_changes (&pwd, result, NULL, 0);

  plen = pwd_need_buflen (&pwd);
  if (plen > buflen)
    {
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
  p = buffer + (buflen - plen);
  buflen -= plen;

  if (nss_getpwuid_r (uid, result, buffer, buflen, errnop) ==
      NSS_STATUS_SUCCESS)
    {
      copy_pwd_changes (result, &pwd, p, plen);
      give_pwd_free (&pwd);
      /* We found the entry.  */
      return NSS_STATUS_SUCCESS;
    }
  else
    {
      /* Give buffer the old len back */
      buflen += plen;
      give_pwd_free (&pwd);
    }
  return NSS_STATUS_RETURN;
}

/* Searches in /etc/passwd and the NSS subsystem for a special user id */
static enum nss_status
internal_getpwuid_r (uid_t uid, struct passwd *result, ent_t *ent,
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
	  /* We need at least 3 characters for one line.  */
	  if (__builtin_expect (buflen < 3, 0))
	    {
	    erange:
	      *errnop = ERANGE;
	      return NSS_STATUS_TRYAGAIN;
	    }

	  fgetpos (ent->stream, &pos);
	  buffer[buflen - 1] = '\xff';
	  p = fgets_unlocked (buffer, buflen, ent->stream);
	  if (p == NULL && feof_unlocked (ent->stream))
	    return NSS_STATUS_NOTFOUND;

	  if (p == NULL || __builtin_expect (buffer[buflen - 1] != '\xff', 0))
	    {
	    erange_reset:
	      fsetpos (ent->stream, &pos);
	      goto erange;
	    }

	  /* Terminate the line for any case.  */
	  buffer[buflen - 1] = '\0';

	  /* Skip leading blanks.  */
	  while (isspace (*p))
	    ++p;
	}
      while (*p == '\0' || *p == '#' ||	/* Ignore empty and comment lines.  */
	     /* Parse the line.  If it is invalid, loop to
	        get the next line of the file to parse.  */
	     !(parse_res = _nss_files_parse_pwent (p, result, data, buflen,
						   errnop)));

      if (__builtin_expect (parse_res == -1, 0))
	/* The parser ran out of space.  */
	goto erange_reset;

      /* This is a real entry.  */
      if (result->pw_name[0] != '+' && result->pw_name[0] != '-')
	{
	  if (result->pw_uid == uid)
	    return NSS_STATUS_SUCCESS;
	  else
	    continue;
	}

      /* -@netgroup */
      if (result->pw_name[0] == '-' && result->pw_name[1] == '@'
	  && result->pw_name[2] != '\0')
	{
	  /* -1, because we remove first two character of pw_name.  */
	  size_t len = strlen (result->pw_name) - 1;
	  char buf[len];
	  enum nss_status status;

	  memcpy (buf, &result->pw_name[2], len);

	  status = getpwuid_plususer (uid, result, buffer, buflen, errnop);
	  if (status == NSS_STATUS_SUCCESS &&
	      innetgr (buf, NULL, result->pw_name, NULL))
	    return NSS_STATUS_NOTFOUND;

	  continue;
	}

      /* +@netgroup */
      if (result->pw_name[0] == '+' && result->pw_name[1] == '@'
	  && result->pw_name[2] != '\0')
	{
	  /* -1, because we remove first two characters of pw_name.  */
	  size_t len = strlen (result->pw_name) - 1;
	  char buf[len];
	  enum nss_status status;

	  memcpy (buf, &result->pw_name[2], len);

	  status = getpwuid_plususer (uid, result, buffer, buflen, errnop);

	  if (status == NSS_STATUS_RETURN)
	    continue;

	  if (status == NSS_STATUS_SUCCESS)
	    {
	      if (innetgr (buf, NULL, result->pw_name, NULL))
		return NSS_STATUS_SUCCESS;
	    }
	  else if (status == NSS_STATUS_RETURN)	/* We couldn't parse the entry */
	    return NSS_STATUS_NOTFOUND;
	  else
	    return status;

	  continue;
	}

      /* -user */
      if (result->pw_name[0] == '-' && result->pw_name[1] != '\0'
	  && result->pw_name[1] != '@')
	{
	  size_t len = strlen (result->pw_name);
	  char buf[len];
	  enum nss_status status;

	  memcpy (buf, &result->pw_name[1], len);

	  status = getpwuid_plususer (uid, result, buffer, buflen, errnop);
	  if (status == NSS_STATUS_SUCCESS &&
	      innetgr (buf, NULL, result->pw_name, NULL))
	    return NSS_STATUS_NOTFOUND;
	  continue;
	}

      /* +user */
      if (result->pw_name[0] == '+' && result->pw_name[1] != '\0'
	  && result->pw_name[1] != '@')
	{
	  size_t len = strlen (result->pw_name);
	  char buf[len];
	  enum nss_status status;

	  memcpy (buf, &result->pw_name[1], len);

	  status = getpwuid_plususer (uid, result, buffer, buflen, errnop);

	  if (status == NSS_STATUS_RETURN)
	    continue;

	  if (status == NSS_STATUS_SUCCESS)
	    {
	      if (strcmp (buf, result->pw_name) == 0)
		return NSS_STATUS_SUCCESS;
	    }
	  else if (status == NSS_STATUS_RETURN)	/* We couldn't parse the entry */
	    return NSS_STATUS_NOTFOUND;
	  else
	    return status;

	  continue;
	}

      /* +:... */
      if (result->pw_name[0] == '+' && result->pw_name[1] == '\0')
	{
	  enum nss_status status;

	  status = getpwuid_plususer (uid, result, buffer, buflen, errnop);
	  if (status == NSS_STATUS_SUCCESS)	/* We found the entry. */
	    break;
	  else if (status == NSS_STATUS_RETURN)	/* We couldn't parse the entry */
	    return NSS_STATUS_NOTFOUND;
	  else
	    return status;
	}
    }
  return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_compat_getpwuid_r (uid_t uid, struct passwd *pwd,
			char *buffer, size_t buflen, int *errnop)
{
  enum nss_status result;
  ent_t ent = {0, 0, TRUE, NULL, {NULL, 0, 0},
               {NULL, NULL, 0, 0, NULL, NULL, NULL}};

  __libc_lock_lock (lock);

  if (ni == NULL)
    init_nss_interface ();

  __libc_lock_unlock (lock);

  result = internal_setpwent (&ent, 0);

  if (result == NSS_STATUS_SUCCESS)
    result = internal_getpwuid_r (uid, pwd, &ent, buffer, buflen, errnop);

  internal_endpwent (&ent);

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

/* returns TRUE if ent->blacklist contains name, else FALSE */
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
