/* Copyright (C) 1991,92,93,95,96,97,98,99 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <stdio-common/_itoa.h>

static int getttyname_r __P ((char *buf, size_t buflen,
			      dev_t mydev, ino_t myino, int save,
			      int *dostat)) internal_function;

static int
internal_function
getttyname_r (buf, buflen, mydev, myino, save, dostat)
     char *buf;
     size_t buflen;
     dev_t mydev;
     ino_t myino;
     int save;
     int *dostat;
{
  struct stat st;
  DIR *dirstream;
  struct dirent *d;
  size_t devlen = strlen (buf);

  dirstream = __opendir (buf);
  if (dirstream == NULL)
    {
      *dostat = -1;
      return errno;
    }

  while ((d = __readdir (dirstream)) != NULL)
    if (((ino_t) d->d_fileno == myino || *dostat)
	&& strcmp (d->d_name, "stdin")
	&& strcmp (d->d_name, "stdout")
	&& strcmp (d->d_name, "stderr"))
      {
	char *cp;
	size_t needed = _D_EXACT_NAMLEN (d) + 1;

	if (needed > buflen)
	  {
	    *dostat = -1;
	    (void) __closedir (dirstream);
	    __set_errno (ERANGE);
	    return ERANGE;
	  }

	cp = __stpncpy (buf + devlen, d->d_name, needed);
	cp[0] = '\0';

	if (__xstat (_STAT_VER, buf, &st) == 0
#ifdef _STATBUF_ST_RDEV
	    && S_ISCHR (st.st_mode) && st.st_rdev == mydev
#else
	    && (ino_t) d->d_fileno == myino && st.st_dev == mydev
#endif
	   )
	  {
	    (void) __closedir (dirstream);
	    __set_errno (save);
	    return 0;
	  }
      }

  (void) __closedir (dirstream);
  __set_errno (save);
  /* It is not clear what to return in this case.  `isatty' says FD
     refers to a TTY but no entry in /dev has this inode.  */
  return ENOTTY;
}

/* Store at most BUFLEN character of the pathname of the terminal FD is
   open on in BUF.  Return 0 on success,  otherwise an error number.  */
int
__ttyname_r (fd, buf, buflen)
     int fd;
     char *buf;
     size_t buflen;
{
  static int dev_pts_available = 1;
  char procname[30];
  struct stat st, st1;
  int dostat = 0;
  int save = errno;
  int ret;

  /* Test for the absolute minimal size.  This makes life easier inside
     the loop.  */
  if (!buf)
    {
      __set_errno (EINVAL);
      return EINVAL;
    }

  if (buflen < sizeof ("/dev/pts/"))
    {
      __set_errno (ERANGE);
      return ERANGE;
    }

  if (!__isatty (fd))
    {
      __set_errno (ENOTTY);
      return ENOTTY;
    }

  /* We try using the /proc filesystem.  */
  *_fitoa_word (fd, __stpcpy (procname, "/proc/self/fd/"), 10, 0) = '\0';

  ret = __readlink (procname, buf, buflen - 1);
  if (ret != -1 && buf[0] != '[')
    return 0;
  if (ret == -1 && errno == ENAMETOOLONG)
    {
      __set_errno (ERANGE);
      return ERANGE;
    }

  if (__fxstat (_STAT_VER, fd, &st) < 0)
    return errno;

  /* Prepare the result buffer.  */
  memcpy (buf, "/dev/pts/", sizeof ("/dev/pts/"));
  buflen -= sizeof ("/dev/pts/") - 1;

  if (dev_pts_available)
    {
      if (__xstat (_STAT_VER, buf, &st1) == 0 && S_ISDIR (st1.st_mode))
	{
#ifdef _STATBUF_ST_RDEV
	  ret = getttyname_r (buf, buflen, st.st_rdev, st.st_ino, save,
			      &dostat);
#else
	  ret = getttyname_r (buf, buflen, st.st_dev, st.st_ino, save,
			      &dostat);
#endif
	}
      else
	{
	  __set_errno (save);
	  ret = ENOENT;
	  dev_pts_available = 0;
	}
    }

  if (ret && dostat != -1)
    {
      buf[sizeof ("/dev/") - 1] = '\0';
      buflen += sizeof ("pts/") - 1;
#ifdef _STATBUF_ST_RDEV
      ret = getttyname_r (buf, buflen, st.st_rdev, st.st_ino, save,
			  &dostat);
#else
      ret = getttyname_r (buf, buflen, st.st_dev, st.st_ino, save,
			  &dostat);
#endif
    }

  if (ret && dostat != -1)
    {
      buf[sizeof ("/dev/") - 1] = '\0';
      dostat = 1;
#ifdef _STATBUF_ST_RDEV
      ret = getttyname_r (buf, buflen, st.st_rdev, st.st_ino,
			  save, &dostat);
#else
      ret = getttyname_r (buf, buflen, st.st_dev, st.st_ino,
			  save, &dostat);
#endif
    }

  return ret;
}

weak_alias (__ttyname_r, ttyname_r)
