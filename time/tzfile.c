/* Copyright (C) 1991, 1992, 1993, 1995 Free Software Foundation, Inc.
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

#include <ansidecl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <limits.h>

#define	NOID
#include <tzfile.h>

int __use_tzfile = 0;

struct ttinfo
  {
    long int offset;		/* Seconds east of GMT.  */
    unsigned char isdst;	/* Used to set tm_isdst.  */
    unsigned char idx;		/* Index into `zone_names'.  */
    unsigned char isstd;	/* Transition times are in standard time.  */
    unsigned char isgmt;	/* Transition times are in GMT.  */
  };

struct leap
  {
    time_t transition;		/* Time the transition takes effect.  */
    long int change;		/* Seconds of correction to apply.  */
  };

static void compute_tzname_max __P ((size_t));

static size_t num_transitions;
static time_t *transitions = NULL;
static unsigned char *type_idxs = NULL;
static size_t num_types;
static struct ttinfo *types = NULL;
static char *zone_names = NULL;
static size_t num_leaps;
static struct leap *leaps = NULL;

#include <endian.h>

/* Decode the four bytes at PTR as a signed integer in network byte order.  */
static inline int
decode (const void *ptr)
{
#if BYTE_ORDER == BIG_ENDIAN
  return *(const int *) ptr;
#else
  const unsigned char *p = ptr;
  int result = 0;

  result = (result << 8) | *p++;
  result = (result << 8) | *p++;
  result = (result << 8) | *p++;
  result = (result << 8) | *p++;

  return result;
#endif
}

void
DEFUN(__tzfile_read, (file), CONST char *file)
{
  size_t num_isstd, num_isgmt;
  register FILE *f;
  struct tzhead tzhead;
  size_t chars;
  register size_t i;

  __use_tzfile = 0;

  if (transitions != NULL)
    free((PTR) transitions);
  transitions = NULL;
  if (type_idxs != NULL)
    free((PTR) type_idxs);
  type_idxs = NULL;
  if (types != NULL)
    free((PTR) types);
  types = NULL;
  if (zone_names != NULL)
    free((PTR) zone_names);
  zone_names = NULL;
  if (leaps != NULL)
    free((PTR) leaps);
  leaps = NULL;

  if (file == NULL || *file == '\0')
    file = TZDEFAULT;

  if (*file != '/')
    {
      static CONST char tzdir[] = TZDIR;
      register CONST unsigned int len = strlen(file) + 1;
      char *new = (char *) __alloca(sizeof(tzdir) + len);
      memcpy(new, tzdir, sizeof(tzdir) - 1);
      new[sizeof(tzdir) - 1] = '/';
      memcpy(&new[sizeof(tzdir)], file, len);
      file = new;
    }

  f = fopen(file, "r");
  if (f == NULL)
    return;

  if (fread((PTR) &tzhead, sizeof(tzhead), 1, f) != 1)
    goto lose;

  num_transitions = (size_t) decode (tzhead.tzh_timecnt);
  num_types = (size_t) decode (tzhead.tzh_typecnt);
  chars = (size_t) decode (tzhead.tzh_charcnt);
  num_leaps = (size_t) decode (tzhead.tzh_leapcnt);
  num_isstd = (size_t) decode (tzhead.tzh_ttisstdcnt);
  num_isgmt = (size_t) decode (tzhead.tzh_ttisgmtcnt);

  if (num_transitions > 0)
    {
      transitions = (time_t *) malloc (num_transitions * sizeof(time_t));
      if (transitions == NULL)
	goto lose;
      type_idxs = (unsigned char *) malloc (num_transitions);
      if (type_idxs == NULL)
	goto lose;
    }
  if (num_types > 0)
    {
      types = (struct ttinfo *) malloc (num_types * sizeof (struct ttinfo));
      if (types == NULL)
	goto lose;
    }
  if (chars > 0)
    {
      zone_names = (char *) malloc (chars);
      if (zone_names == NULL)
	goto lose;
    }
  if (num_leaps > 0)
    {
      leaps = (struct leap *) malloc (num_leaps * sizeof (struct leap));
      if (leaps == NULL)
	goto lose;
    }

  if (fread((PTR) transitions, 4, num_transitions, f) != num_transitions ||
      fread((PTR) type_idxs, 1, num_transitions, f) != num_transitions)
    goto lose;

  if (BYTE_ORDER != BIG_ENDIAN || sizeof (time_t) != 4)
    {
      /* Decode the transition times, stored as 4-byte integers in
	 network (big-endian) byte order.  We work from the end of
	 the array so as not to clobber the next element to be
	 processed when sizeof (time_t) > 4.  */
      i = num_transitions;
      while (num_transitions-- > 0)
	transitions[i] = decode ((char *) transitions + i*4);
    }

  for (i = 0; i < num_types; ++i)
    {
      unsigned char x[4];
      if (fread((PTR) x, 1, 4, f) != 4 ||
	  fread((PTR) &types[i].isdst, 1, 1, f) != 1 ||
	  fread((PTR) &types[i].idx, 1, 1, f) != 1)
	goto lose;
      types[i].offset = (long int) decode (x);
    }

  if (fread((PTR) zone_names, 1, chars, f) != chars)
    goto lose;

  for (i = 0; i < num_leaps; ++i)
    {
      unsigned char x[4];
      if (fread((PTR) x, 1, sizeof(x), f) != sizeof(x))
	goto lose;
      leaps[i].transition = (time_t) decode (x);
      if (fread((PTR) x, 1, sizeof(x), f) != sizeof(x))
	goto lose;
      leaps[i].change = (long int) decode (x);
    }

  for (i = 0; i < num_isstd; ++i)
    {
      char c = getc(f);
      if (c == EOF)
	goto lose;
      types[i].isstd = c != 0;
    }
  while (i < num_types)
    types[i++].isstd = 0;

  for (i = 0; i < num_isgmt; ++i)
    {
      char c = getc(f);
      if (c == EOF)
	goto lose;
      types[i].isgmt = c != 0;
    }
  while (i < num_types)
    types[i++].isgmt = 0;

  (void) fclose(f);

  compute_tzname_max (chars);
  
  __use_tzfile = 1;
  return;

 lose:;
  (void) fclose(f);
}

/* The user specified a hand-made timezone, but not its DST rules.
   We will use the names and offsets from the user, and the rules
   from the TZDEFRULES file.  */

void
DEFUN(__tzfile_default, (std, dst, stdoff, dstoff),
      char *std AND char *dst AND
      long int stdoff AND long int dstoff)
{
  size_t stdlen, dstlen, i;
  long int rule_offset, rule_stdoff, rule_dstoff;
  int isdst;

  __tzfile_read (TZDEFRULES);
  if (!__use_tzfile)
    return;

  if (num_types < 2)
    {
      __use_tzfile = 0;
      return;
    }

  /* Ignore the zone names read from the file.  */
  free (zone_names);

  /* Use the names the user specified.  */
  stdlen = strlen (std) + 1;
  dstlen = strlen (dst) + 1;
  zone_names = malloc (stdlen + dstlen);
  if (zone_names == NULL)
    {
      __use_tzfile = 0;
      return;
    }
  memcpy (zone_names, std, stdlen);
  memcpy (&zone_names[stdlen], dst, dstlen);

  /* Find the standard and daylight time offsets used by the rule file.
     We choose the offsets in the types of each flavor that are
     transitioned to earliest in time.  */
  rule_stdoff = rule_dstoff = 0;
  for (i = 0; i < num_transitions; ++i)
    {
      if (!rule_stdoff && !types[type_idxs[i]].isdst)
	rule_stdoff = types[type_idxs[i]].offset;
      if (!rule_dstoff && types[type_idxs[i]].isdst)
	rule_dstoff = types[type_idxs[i]].offset;
      if (rule_stdoff && rule_dstoff)
	break;
    }

  /* Now correct the transition times for the user-specified standard and
     daylight offsets from GMT.  */
  isdst = 0;
  rule_offset = rule_offset;
  for (i = 0; i < num_transitions; ++i)
    {
      struct ttinfo *trans_type = &types[type_idxs[i]];

      /* We will use only types 0 (standard) and 1 (daylight).
	 Fix up this transition to point to whichever matches
	 the flavor of its original type.  */
      type_idxs[i] = trans_type->isdst;

      if (trans_type->isgmt)
	/* The transition time is in GMT.  No correction to apply.  */ ;
      else if (isdst && !trans_type->isstd)
	/* The type says this transition is in "local wall clock time", and
	   wall clock time as of the previous transition was DST.  Correct
	   for the difference between the rule's DST offset and the user's
	   DST offset.  */
	transitions[i] += dstoff - rule_dstoff;
      else
	/* This transition is in "local wall clock time", and wall clock
	   time as of this iteration is non-DST.  Correct for the
	   difference between the rule's standard offset and the user's
	   standard offset.  */
	transitions[i] += stdoff - rule_stdoff;

      /* The DST state of "local wall clock time" for the next iteration is
	 as specified by this transition.  */
      isdst = trans_type->isdst;
    }

  /* Reset types 0 and 1 to describe the user's settings.  */
  types[0].idx = 0;
  types[0].offset = stdoff;
  types[0].isdst = 0;
  types[1].idx = stdlen;
  types[1].offset = dstoff;
  types[1].isdst = 1;

  compute_tzname_max (stdlen + dstlen);
}

int
DEFUN(__tzfile_compute, (timer, leap_correct, leap_hit),
      time_t timer AND long int *leap_correct AND int *leap_hit)
{
  struct ttinfo *info;
  register size_t i;

  if (num_transitions == 0 || timer < transitions[0])
    {
      /* TIMER is before any transition (or there are no transitions).
	 Choose the first non-DST type
	 (or the first if they're all DST types).  */
      i = 0;
      while (i < num_types && types[i].isdst)
	++i;
      if (i == num_types)
	i = 0;
    }
  else
    {
      /* Find the first transition after TIMER, and
	 then pick the type of the transition before it.  */
      for (i = 1; i < num_transitions; ++i)
	if (timer < transitions[i])
	  break;
      i = type_idxs[i - 1];
    }

  info = &types[i];
  __daylight = info->isdst;
  __timezone = info->offset;
  for (i = 0; i < num_types && i < sizeof (__tzname) / sizeof (__tzname[0]);
       ++i)
    __tzname[types[i].isdst] = &zone_names[types[i].idx];
  if (info->isdst < sizeof (__tzname) / sizeof (__tzname[0]))
    __tzname[info->isdst] = &zone_names[info->idx];

  *leap_correct = 0L;
  *leap_hit = 0;

  /* Find the last leap second correction transition time before TIMER.  */
  i = num_leaps;
  do
    if (i-- == 0)
      return 1;
  while (timer < leaps[i].transition);

  /* Apply its correction.  */
  *leap_correct = leaps[i].change;

  if (timer == leaps[i].transition && /* Exactly at the transition time.  */
      ((i == 0 && leaps[i].change > 0) ||
       leaps[i].change > leaps[i - 1].change))
    {
      *leap_hit = 1;
      while (i > 0 &&
	     leaps[i].transition == leaps[i - 1].transition + 1 &&
	     leaps[i].change == leaps[i - 1].change + 1)
	{
	  ++*leap_hit;
	  --i;
	}
    }

  return 1;
}

void
DEFUN(compute_tzname_max, (chars), size_t chars)
{
  extern long int __tzname_cur_max; /* Defined in __tzset.c. */

  const char *p;

  p = zone_names;
  do
    {
      const char *start = p;
      while (*p != '\0')
	++p;
      if (p - start > __tzname_cur_max)
	__tzname_cur_max = p - start;
    } while (++p < &zone_names[chars]);
}
