/* Copyright (C) 1994, 1996 Free Software Foundation, Inc.
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
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#include <errno.h>
#include <sys/resource.h>
#include <sys/sysmp.h>

int
setpriority (which, who, prio)
     enum __priority_which which;
     int who;
     int prio;
{
  switch (which)
    {
    case PRIO_PROCESS:
      return __sysmp (MP_SCHED, MPTS_RENICE_PROC, who, prio);
    case PRIO_PGRP:
      return __sysmp (MP_SCHED, MPTS_RENICE_PGRP, who, prio);
    case PRIO_USER:
      return __sysmp (MP_SCHED, MPTS_RENICE_USER, who, prio);
    }

  __set_errno (EINVAL);
  return -1;
}
