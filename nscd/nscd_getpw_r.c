/* Copyright (C) 1998, 1999, 2003, 2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@uni-paderborn.de>, 1998.

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

#include <errno.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <not-cancel.h>
#include <stdio-common/_itoa.h>

#include "nscd-client.h"
#include "nscd_proto.h"

int __nss_not_use_nscd_passwd;

static int nscd_getpw_r (const char *key, size_t keylen, request_type type,
			 struct passwd *resultbuf, char *buffer,
			 size_t buflen, struct passwd **result)
     internal_function;

int
__nscd_getpwnam_r (const char *name, struct passwd *resultbuf, char *buffer,
		   size_t buflen, struct passwd **result)
{
  if (name == NULL)
    return -1;

  return nscd_getpw_r (name, strlen (name) + 1, GETPWBYNAME, resultbuf,
		       buffer, buflen, result);
}

int
__nscd_getpwuid_r (uid_t uid, struct passwd *resultbuf, char *buffer,
		   size_t buflen, struct passwd **result)
{
  char buf[3 * sizeof (uid_t)];
  buf[sizeof (buf) - 1] = '\0';
  char *cp = _itoa_word (uid, buf + sizeof (buf) - 1, 10, 0);

  return nscd_getpw_r (cp, buf + sizeof (buf) - cp, GETPWBYUID, resultbuf,
		       buffer, buflen, result);
}


static int
internal_function
nscd_getpw_r (const char *key, size_t keylen, request_type type,
	      struct passwd *resultbuf, char *buffer, size_t buflen,
	      struct passwd **result)
{
  pw_response_header pw_resp;
  int sock = __nscd_open_socket (key, keylen, type, &pw_resp,
				 sizeof (pw_resp));
  if (sock == -1)
    {
      __nss_not_use_nscd_passwd = 1;
      return -1;
    }

  /* No value found so far.  */
  int retval = -1;
  *result = NULL;

  if (__builtin_expect (pw_resp.found == -1, 0))
    {
      /* The daemon does not cache this database.  */
      __nss_not_use_nscd_passwd = 1;
      goto out;
    }

  if (pw_resp.found == 1)
    {
      char *p = buffer;
      size_t total = (pw_resp.pw_name_len + pw_resp.pw_passwd_len
		      + pw_resp.pw_gecos_len + pw_resp.pw_dir_len
		      + pw_resp.pw_shell_len);

      if (__builtin_expect (buflen < total, 0))
	{
	  __set_errno (ERANGE);
	  retval = ERANGE;
	  goto out;
	}

      /* Set the information we already have.  */
      resultbuf->pw_uid = pw_resp.pw_uid;
      resultbuf->pw_gid = pw_resp.pw_gid;

      /* get pw_name */
      resultbuf->pw_name = p;
      p += pw_resp.pw_name_len;
      /* get pw_passwd */
      resultbuf->pw_passwd = p;
      p += pw_resp.pw_passwd_len;
      /* get pw_gecos */
      resultbuf->pw_gecos = p;
      p += pw_resp.pw_gecos_len;
      /* get pw_dir */
      resultbuf->pw_dir = p;
      p += pw_resp.pw_dir_len;
      /* get pw_pshell */
      resultbuf->pw_shell = p;

      ssize_t nbytes = TEMP_FAILURE_RETRY (__read (sock, buffer, total));

      if (nbytes == (ssize_t) total)
	{
	  retval = 0;
	  *result = resultbuf;
	}
    }
  else
    {
      /* The `errno' to some value != ERANGE.  */
      __set_errno (ENOENT);
      /* Even though we have not found anything, the result is zero.  */
      retval = 0;
    }

 out:
  close_not_cancel_no_status (sock);

  return retval;
}
