/* Find path of executable.
   Copyright (C) 1998-2000, 2002, 2004, 2008 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <ldsodefs.h>
#include <sysdep.h>

#include <dl-dst.h>

/* On Linux >= 2.1 systems which have the dcache implementation we can get
   the path of the application from the /proc/self/exe symlink.  Try this
   first and fall back on the generic method if necessary.  */

const char *
_dl_get_origin (void)
{
#ifndef __ASSUME_AT_EXECFN
  char linkval[PATH_MAX];
#endif
  char *str;
  char *result = (char *) -1l;
  int len;

  str = GLRO(dl_execfn);
#ifndef __ASSUME_AT_EXECFN
  if (str == NULL)
    {
      INTERNAL_SYSCALL_DECL (err);

      len = INTERNAL_SYSCALL (readlink, err, 3, "/proc/self/exe", linkval,
			      sizeof (linkval));
      if (! INTERNAL_SYSCALL_ERROR_P (len, err)
	  && len > 0 && linkval[0] != '[')
	str = linkval;
    }
  else
#endif
    len = strlen (str);

#ifndef __ASSUME_AT_EXECFN
  if (str == NULL)
    {
      /* We use the environment variable LD_ORIGIN_PATH.  If it is set make
	 a copy and strip out trailing slashes.  */
      if (GLRO(dl_origin_path) != NULL)
	{
	  size_t len = strlen (GLRO(dl_origin_path));
	  result = (char *) malloc (len + 1);
	  if (result == NULL)
	    result = (char *) -1;
	  else
	    {
	      char *cp = __mempcpy (result, GLRO(dl_origin_path), len);
	      while (cp > result + 1 && cp[-1] == '/')
		--cp;
	      *cp = '\0';
	    }
	}
    }
  else
#endif
    {
      /* We can use this value.  */
      assert (str[0] == '/');
      while (len > 1 && str[len - 1] != '/')
	--len;
      result = (char *) malloc (len + 1);
      if (result == NULL)
	result = (char *) -1;
      else if (len == 1)
	memcpy (result, "/", 2);
      else
	*((char *) __mempcpy (result, str, len - 1)) = '\0';
    }

  return result;
}
