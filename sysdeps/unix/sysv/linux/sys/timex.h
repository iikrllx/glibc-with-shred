/* Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
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

#ifndef	_SYS_TIMEX_H
#define	_SYS_TIMEX_H	1

#include <features.h>
#include <sys/time.h>

/* These definitions from linux/timex.h as of 2.1.130.  */

struct timex
{
  unsigned int modes;	/* mode selector */
  long offset;		/* time offset (usec) */
  long freq;		/* frequency offset (scaled ppm) */
  long maxerror;	/* maximum error (usec) */
  long esterror;	/* estimated error (usec) */
  int status;		/* clock command/status */
  long constant;	/* pll time constant */
  long precision;	/* clock precision (usec) (read only) */
  long tolerance;	/* clock frequency tolerance (ppm) (read only) */
  struct timeval time;	/* (read only) */
  long tick;		/* (modified) usecs between clock ticks */

  long ppsfreq;         /* pps frequency (scaled ppm) (ro) */
  long jitter;          /* pps jitter (us) (ro) */
  int shift;            /* interval duration (s) (shift) (ro) */
  long stabil;          /* pps stability (scaled ppm) (ro) */
  long jitcnt;          /* jitter limit exceeded (ro) */
  long calcnt;          /* calibration intervals (ro) */
  long errcnt;          /* calibration errors (ro) */
  long stbcnt;          /* stability limit exceeded (ro) */

  /* ??? */
  int  :32; int  :32; int  :32; int  :32;
  int  :32; int  :32; int  :32; int  :32;
  int  :32; int  :32; int  :32; int  :32;
};

/* Mode codes (timex.mode) */
#define ADJ_OFFSET		0x0001	/* time offset */
#define ADJ_FREQUENCY		0x0002	/* frequency offset */
#define ADJ_MAXERROR		0x0004	/* maximum time error */
#define ADJ_ESTERROR		0x0008	/* estimated time error */
#define ADJ_STATUS		0x0010	/* clock status */
#define ADJ_TIMECONST		0x0020	/* pll time constant */
#define ADJ_TICK		0x4000	/* tick value */
#define ADJ_OFFSET_SINGLESHOT	0x8001	/* old-fashioned adjtime */

/* xntp 3.4 compatibility names */
#define MOD_OFFSET	ADJ_OFFSET
#define MOD_FREQUENCY	ADJ_FREQUENCY
#define MOD_MAXERROR	ADJ_MAXERROR
#define MOD_ESTERROR	ADJ_ESTERROR
#define MOD_STATUS	ADJ_STATUS
#define MOD_TIMECONST	ADJ_TIMECONST
#define MOD_CLKB	ADJ_TICK
#define MOD_CLKA	ADJ_OFFSET_SINGLESHOT /* 0x8000 in original */


/* Status codes (timex.status) */
#define STA_PLL		0x0001	/* enable PLL updates (rw) */
#define STA_PPSFREQ	0x0002	/* enable PPS freq discipline (rw) */
#define STA_PPSTIME	0x0004	/* enable PPS time discipline (rw) */
#define STA_FLL		0x0008	/* select frequency-lock mode (rw) */

#define STA_INS		0x0010	/* insert leap (rw) */
#define STA_DEL		0x0020	/* delete leap (rw) */
#define STA_UNSYNC	0x0040	/* clock unsynchronized (rw) */
#define STA_FREQHOLD	0x0080	/* hold frequency (rw) */

#define STA_PPSSIGNAL	0x0100	/* PPS signal present (ro) */
#define STA_PPSJITTER	0x0200	/* PPS signal jitter exceeded (ro) */
#define STA_PPSWANDER	0x0400	/* PPS signal wander exceeded (ro) */
#define STA_PPSERROR	0x0800	/* PPS signal calibration error (ro) */

#define STA_CLOCKERR	0x1000	/* clock hardware fault (ro) */

#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
    STA_PPSERROR | STA_CLOCKERR) /* read-only bits */

/* Clock states (time_state) */
#define TIME_OK		0	/* clock synchronized, no leap second */
#define TIME_INS	1	/* insert leap second */
#define TIME_DEL	2	/* delete leap second */
#define TIME_OOP	3	/* leap second in progress */
#define TIME_WAIT	4	/* leap second has occurred */
#define TIME_ERROR	5	/* clock not synchronized */
#define TIME_BAD	TIME_ERROR /* bw compat */

__BEGIN_DECLS

extern int __adjtimex __P ((struct timex *__ntx));
extern int adjtimex __P ((struct timex *__ntx));

__END_DECLS

#endif /* sys/timex.h */
