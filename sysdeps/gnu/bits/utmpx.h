/* Structures and defenitions for the user accounting database.  GNU version.
   Copyright (C) 1997 Free Software Foundation, Inc.
   Contributed by Mark Kettenis <kettenis@phys.uva.nl>, 1997.

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

#ifndef _UTMPX_H
#error "Never use <bits/utmpx.h> directly; include <utmpx.h> instead."
#endif

#include <bits/types.h>
#include <sys/time.h>


#define __UT_LINESIZE	32
#define __UT_NAMESIZE	32
#define __UT_HOSTSIZE	256

   
/* The structure describing the status of a terminated process.  This
   type is used in `struct utmpx' below.  */
struct __exit_status
{
  short int e_termination;	/* Process termination status.  */
  short int e_exit;		/* Process exit status.  */
};


/* The structure describing an entry in the user accounting database.  */
struct utmpx
{
  short int ut_type;		/* Type of login.  */
  __pid_t ut_pid;		/* Process ID of login process.  */
  char ut_line[__UT_LINESIZE];	/* Devicename.  */
  char ut_id[4];		/* Inittab ID. */
  char ut_user[__UT_NAMESIZE];	/* Username.  */
  char ut_host[__UT_HOSTSIZE];	/* Hostname for remote login.  */
  struct __exit_status ut_exit;	/* Exit status of a process marked
				   as DEAD_PROCESS.  */
  long ut_session;		/* Session ID, used for windowing.  */
  struct timeval ut_tv;		/* Time entry was made.  */
  __int32_t ut_addr_v6[4];	/* Internet address of remote host.  */
  char pad[20];			/* Reserved for future use.  */
};


/* Values for the `ut_type' field of a `struct utmp'.  */
#define EMPTY		0	/* No valid user accounting information.  */

#define RUN_LVL		1	/* The system's runlevel.  */
#define BOOT_TIME	2	/* Time of system boot.  */
#define NEW_TIME	3	/* Time after system clock changed.  */
#define OLD_TIME	4	/* Time when system clock changed.  */

#define INIT_PROCESS	5	/* Process spawned by the init process.  */
#define LOGIN_PROCESS	6	/* Session leader of a logged in user.  */
#define USER_PROCESS	7	/* Normal process.  */
#define DEAD_PROCESS	8	/* Terminated process.  */








