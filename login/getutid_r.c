/* Copyright (C) 1996 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>
   and Paul Janzen <pcj@primenet.com>, 1996.

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
#include <bits/libc-lock.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>

#include "utmp-private.h"


/* We have to use the lock in getutent_r.c.  */
__libc_lock_define (extern, __libc_utmp_lock)

/* The jump table is also in getutent_r.c.  */
extern struct utfuncs *__libc_utmp_jump_table;


int
__getutid_r (const struct utmp *id, struct utmp *buffer, struct utmp **result)
{
#if (_HAVE_UT_ID - 0) && (_HAVE_UT_TYPE - 0)
  int retval = -1;

  /* Test whether ID has any of the legal types.  */
  if (id->ut_type != RUN_LVL && id->ut_type != BOOT_TIME
      && id->ut_type != OLD_TIME && id->ut_type != NEW_TIME
      && id->ut_type != INIT_PROCESS && id->ut_type != LOGIN_PROCESS
      && id->ut_type != USER_PROCESS && id->ut_type != DEAD_PROCESS)
    /* No, using '<' and '>' for the test is not possible.  */
    {
      __set_errno (EINVAL);
      *result = NULL;
      return -1;
    }

  __libc_lock_lock (__libc_utmp_lock);

  /* Not yet initialized.  */
  if ((*__libc_utmp_jump_table->setutent) (0))
    retval = (*__libc_utmp_jump_table->getutid_r) (id, buffer, result);
  else
    *result = NULL;

  __libc_lock_unlock (__libc_utmp_lock);

  return retval;
#else	/* !_HAVE_UT_ID && !_HAVE_UT_TYPE */
  __set_errno (ENOSYS);
  return -1;
#endif
}
weak_alias (__getutid_r, getutid_r)
