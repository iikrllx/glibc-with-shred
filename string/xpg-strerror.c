/* Copyright (C) 1991, 1993, 1995-1998, 2000, 2002, 2004, 2010, 2011
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>


/* Fill buf with a string describing the errno code in ERRNUM.  */
int
__xpg_strerror_r (int errnum, char *buf, size_t buflen)
{
  const char *estr = __strerror_r (errnum, buf, buflen);
  size_t estrlen = strlen (estr);

  if (estr == buf)
    {
      assert (errnum < 0 || errnum >= _sys_nerr_internal
	      || _sys_errlist_internal[errnum] == NULL);
      return EINVAL;
    }
  assert (errnum >= 0 && errnum < _sys_nerr_internal
	  && _sys_errlist_internal[errnum] != NULL);

  /* Terminate the string in any case.  */
  if (buflen > 0)
    *((char *) __mempcpy (buf, estr, MIN (buflen - 1, estrlen))) = '\0';

  return buflen <= estrlen ? ERANGE : 0;
}
