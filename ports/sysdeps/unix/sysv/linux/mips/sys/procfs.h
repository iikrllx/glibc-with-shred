/* Copyright (C) 1996, 1997, 1999, 2000, 2002, 2003, 2004
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
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _SYS_PROCFS_H
#define _SYS_PROCFS_H	1

/* This is somehow modelled after the file of the same name on SysVr4
   systems.  It provides a definition of the core file format for ELF
   used on Linux.  */

#include <features.h>
#include <sgidefs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sgidefs.h>

/* ELF register definitions */
#define ELF_NGREG	45
#define ELF_NFPREG	33

#if _MIPS_SIM == _ABIN32
__extension__ typedef unsigned long long elf_greg_t;
#else
typedef unsigned long elf_greg_t;
#endif
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

typedef double elf_fpreg_t;
typedef elf_fpreg_t elf_fpregset_t[ELF_NFPREG];

__BEGIN_DECLS

struct elf_siginfo
  {
    int si_signo;			/* Signal number.  */
    int si_code;			/* Extra code.  */
    int si_errno;			/* Errno.  */
  };


/* Definitions to generate Intel SVR4-like core files.  These mostly
   have the same names as the SVR4 types with "elf_" tacked on the
   front to prevent clashes with linux definitions, and the typedef
   forms have been avoided.  This is mostly like the SVR4 structure,
   but more Linuxy, with things that Linux does not support and which
   gdb doesn't really use excluded.  Fields present but not used are
   marked with "XXX".  */
struct elf_prstatus
  {
    struct elf_siginfo pr_info;		/* Info associated with signal.  */
    short int pr_cursig;		/* Current signal.  */
#if _MIPS_SIM == _ABIN32
    __extension__ unsigned long long int pr_sigpend;
    __extension__ unsigned long long int pr_sighold;
#else
    unsigned long int pr_sigpend;	/* Set of pending signals.  */
    unsigned long int pr_sighold;	/* Set of held signals.  */
#endif
    __pid_t pr_pid;
    __pid_t pr_ppid;
    __pid_t pr_pgrp;
    __pid_t pr_sid;
    struct timeval pr_utime;		/* User time.  */
    struct timeval pr_stime;		/* System time.  */
    struct timeval pr_cutime;		/* Cumulative user time.  */
    struct timeval pr_cstime;		/* Cumulative system time.  */
    elf_gregset_t pr_reg;		/* GP registers.  */
    int pr_fpvalid;			/* True if math copro being used.  */
  };


#define ELF_PRARGSZ     (80)    /* Number of chars for args */

struct elf_prpsinfo
  {
    char pr_state;			/* Numeric process state.  */
    char pr_sname;			/* Char for pr_state.  */
    char pr_zomb;			/* Zombie.  */
    char pr_nice;			/* Nice val.  */
#if _MIPS_SIM == _ABIN32
    __extension__ unsigned long long int pr_flag;
#else
    unsigned long int pr_flag;		/* Flags.  */
#endif
    long pr_uid;
    long pr_gid;
    int pr_pid, pr_ppid, pr_pgrp, pr_sid;
    /* Lots missing */
    char pr_fname[16];			/* Filename of executable.  */
    char pr_psargs[ELF_PRARGSZ];	/* Initial part of arg list.  */
  };


/* Addresses.  */
typedef void *psaddr_t;

/* Register sets.  Linux has different names.  */
typedef elf_gregset_t prgregset_t;
typedef elf_fpregset_t prfpregset_t;

/* We don't have any differences between processes and threads,
   therefore habe only ine PID type.  */
typedef __pid_t lwpid_t;


typedef struct elf_prstatus prstatus_t;
typedef struct elf_prpsinfo prpsinfo_t;

__END_DECLS

#endif	/* sys/procfs.h */
