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

#include <alloca.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>
#include <sys/file.h>
#include <sys/stat.h>


/* XXX An alternative solution would be to call a SUID root program
   which write the new value.  */

int
__pututline_r (const struct utmp *id, struct utmp_data *utmp_data)
{
  struct stat st;
  int result = 0;

#if _HAVE_UT_TYPE - 0
  /* Test whether ID has any of the legal types because we have to
     prevent illegal entries.  */
  if (id->ut_type != RUN_LVL && id->ut_type != BOOT_TIME
      && id->ut_type != OLD_TIME && id->ut_type != NEW_TIME
      && id->ut_type != INIT_PROCESS && id->ut_type != LOGIN_PROCESS
      && id->ut_type != USER_PROCESS && id->ut_type != DEAD_PROCESS)
    /* No, using '<' and '>' for the test is not possible.  */
    {
      errno = EINVAL;
      return -1;
    }
#endif

  /* Open utmp file if not already done.  */
  if (utmp_data->ut_fd == -1)
    {
      setutent_r (utmp_data);
      if (utmp_data->ut_fd == -1)
	return -1;
    }

#if _HAVE_UT_ID - 0
  /* Check whether we need to reposition.  Repositioning is necessary
     either if the data in UTMP_DATA is not valid or if the ids don't
     match: */
  if (id->ut_id[0]
      && (utmp_data->loc_utmp < (off_t) sizeof (struct utmp)
	  || strncmp (utmp_data->ubuf.ut_id, id->ut_id,
		      sizeof (id->ut_id)) != 0))
    {
      /* We must not overwrite the data in UTMP_DATA since ID may be
	 aliasing it.  */
      struct utmp_data *data_tmp = alloca (sizeof (*data_tmp));
      struct utmp *dummy;

      *data_tmp = *utmp_data;
      utmp_data = data_tmp;

      if (getutid_r (id, &dummy, utmp_data) < 0 && errno != ESRCH)
	return -1;
    }
#endif

  /* Try to lock the file.  */
  if (flock (utmp_data->ut_fd, LOCK_EX | LOCK_NB) < 0 && errno != ENOSYS)
    {
      /* Oh, oh.  The file is already locked.  Wait a bit and try again.  */
      sleep (1);

      /* This time we ignore the error.  */
      (void) flock (utmp_data->ut_fd, LOCK_EX | LOCK_NB);
    }

  /* Find out how large the file is.  */
  result = fstat (utmp_data->ut_fd, &st);

  if (result >= 0)
    /* Position file correctly.  */
    if (utmp_data->loc_utmp < (off_t) sizeof (struct utmp)
	|| utmp_data->loc_utmp - sizeof (struct utmp) > st.st_size)
      /* Not located at any valid entry.  Add at the end.  */
      {
	result = lseek (utmp_data->ut_fd, 0L, SEEK_END);
	if (result >= 0)
	  /* Where we'll be if the write succeeds.  */
	  utmp_data->loc_utmp = st.st_size + sizeof (struct utmp);
      }
    else
      result =
	lseek (utmp_data->ut_fd, utmp_data->loc_utmp - sizeof (struct utmp),
	       SEEK_SET);

  if (result >= 0)
    /* Write the new data.  */
    if (write (utmp_data->ut_fd, id, sizeof (struct utmp))
	!= sizeof (struct utmp))
      {
	/* If we appended a new record this is only partially written.
	   Remove it.  */
	if (utmp_data->loc_utmp > st.st_size)
	  {
	    (void) ftruncate (utmp_data->ut_fd, st.st_size);
	    utmp_data->loc_utmp = st.st_size;
	  }

	result = -1;
      }

  /* And unlock the file.  */
  (void) flock (utmp_data->ut_fd, LOCK_UN);

  return result;
}
weak_alias (__pututline_r, pututline_r)
