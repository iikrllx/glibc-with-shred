/* Copyright (C) 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <string.h>
#include <unistd.h>
#include <utmp.h>


void
logwtmp (const char *line, const char *name, const char *host)
{
  struct utmp_data data;
  struct utmp ut;

  /* Tell that we want to use the UTMP file.  */
  if (utmpname (_PATH_WTMP) == 0)
    return;

  /* Open UTMP file.  */
  setutent_r (&data);

  /* Position at end of file.  */
  data.loc_utmp = lseek (data.ut_fd, 0, SEEK_END);
  if (data.loc_utmp == -1)
    return;

  /* Set information in new entry.  */
  bzero (&ut, sizeof (ut));
#if _HAVE_UT_TYPE - 0
  ut.ut_type = USER_PROCESS;
#endif
  strncpy (ut.ut_line, line, UT_LINESIZE);
  strncpy (ut.ut_name, name, UT_NAMESIZE);
  strncpy (ut.ut_host, host, UT_HOSTSIZE);

#if _HAVE_UT_TV - 0
  gettimeofday (&ut.ut_tv, NULL);
#else
  time (&ut.ut_time);
#endif

  /* Write the entry.  */
  pututline_r (&ut, &data);

  /* Close UTMP file.  */
  endutent_r (&data);

}
