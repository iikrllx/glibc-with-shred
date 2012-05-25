/* Semctl for architectures where word sized unions are passed indirectly
   Copyright (C) 1995-2012 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.ai.mit.edu>, August 1995.

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

#include <errno.h>
#include <stdarg.h>
#include <sys/sem.h>
#include <ipc_priv.h>

#include <sysdep.h>
#include <string.h>
#include <sys/syscall.h>

#include <shlib-compat.h>

struct __old_semid_ds
{
  struct __old_ipc_perm sem_perm;	/* operation permission struct */
  __time_t sem_otime;			/* last semop() time */
  __time_t sem_ctime;			/* last time changed by semctl() */
  struct sem *__sembase;		/* ptr to first semaphore in array */
  struct sem_queue *__sem_pending;	/* pending operations */
  struct sem_queue *__sem_pending_last; /* last pending operation */
  struct sem_undo *__undo;		/* ondo requests on this array */
  unsigned short int sem_nsems;		/* number of semaphores in set */
};

/* Define a `union semun' suitable for Linux here.  */
union semun
{
  int val;			/* value for SETVAL */
  struct semid_ds *buf;		/* buffer for IPC_STAT & IPC_SET */
  unsigned short int *array;	/* array for GETALL & SETALL */
  struct seminfo *__buf;	/* buffer for IPC_INFO */
  struct __old_semid_ds *__old_buf;
};

#include <bp-checks.h>
#include <bp-semctl.h>		/* definition of CHECK_SEMCTL needs union semum */

/* Return identifier for array of NSEMS semaphores associated with
   KEY.  */
#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_2)
int __old_semctl (int semid, int semnum, int cmd, ...);
#endif
int __new_semctl (int semid, int semnum, int cmd, ...);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_2)
int
attribute_compat_text_section
__old_semctl (int semid, int semnum, int cmd, ...)
{
  union semun arg;
  va_list ap;

  /* Get the argument only if required.  */
  arg.buf = NULL;
  switch (cmd)
    {
    case SETVAL:	/* arg.val */
    case GETALL:	/* arg.array */
    case SETALL:
    case IPC_STAT:	/* arg.buf */
    case IPC_SET:
    case SEM_STAT:
    case IPC_INFO:	/* arg.__buf */
    case SEM_INFO:
      va_start (ap, cmd);
      arg = va_arg (ap, union semun);
      va_end (ap);
      break;
    }

  return INLINE_SYSCALL (ipc, 5, IPCOP_semctl, semid, semnum, cmd,
			 CHECK_SEMCTL (&arg, semid, cmd));
}
compat_symbol (libc, __old_semctl, semctl, GLIBC_2_0);
#endif

int
__new_semctl (int semid, int semnum, int cmd, ...)
{
  union semun arg;
  va_list ap;

  /* Get the argument only if required.  */
  arg.buf = NULL;
  switch (cmd)
    {
    case SETVAL:	/* arg.val */
    case GETALL:	/* arg.array */
    case SETALL:
    case IPC_STAT:	/* arg.buf */
    case IPC_SET:
    case SEM_STAT:
    case IPC_INFO:	/* arg.__buf */
    case SEM_INFO:
      va_start (ap, cmd);
      arg = va_arg (ap, union semun);
      va_end (ap);
      break;
    }

  return INLINE_SYSCALL (ipc, 5, IPCOP_semctl, semid, semnum, cmd | __IPC_64,
			 CHECK_SEMCTL (&arg, semid, cmd | __IPC_64));
}

versioned_symbol (libc, __new_semctl, semctl, GLIBC_2_2);
