/* Copyright (C) 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

#include <fmtmsg.h>
#include <libc-lock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>


/* We have global data, protect the modification.  */
__libc_lock_define_initialized (static, lock)


enum
{
  label_mask = 0x01,
  severity_mask = 0x02,
  text_mask = 0x04,
  action_mask = 0x08,
  tag_mask = 0x10,
  all_mask = label_mask | severity_mask | text_mask | action_mask | tag_mask
};

static struct
{
  const char *name;
  size_t len;
} keywords[] =
  {
    { "label", 5 },
    { "severity", 8 },
    { "text", 4 },
    { "action", 6},
    { "tag", 3 }
  };
#define NKEYWORDS (sizeof( keywords) / sizeof (keywords[0]))


struct severity_info
{
  int severity;
  const char *string;
  struct severity_info *next;
};


/* List of known severities.  */
static const struct severity_info nosev =
{
  MM_NOSEV, "", NULL
};
static const struct severity_info haltsev =
{
  MM_HALT, "HALT", (struct severity_info *) &nosev
};
static const struct severity_info errorsev =
{
  MM_ERROR, "ERROR", (struct severity_info *) &haltsev
};
static const struct severity_info warningsev =
{
  MM_WARNING, "WARNING", (struct severity_info *) &errorsev
};
static const struct severity_info infosev =
{
  MM_INFO, "INFO", (struct severity_info *) &warningsev
};

/* Start of the list.  */
static struct severity_info *severity_list = (struct severity_info *) &infosev;


/* Prototypes for local functions.  */
static int internal_addseverity (int severity, const char *string);


int
fmtmsg (long int classification, const char *label, int severity,
	const char *text, const char *action, const char *tag)
{
  static int print = -1;
  int result = MM_OK;
  struct severity_info *severity_rec;

  if (print == -1)
    {
      __libc_lock_lock (lock);

      if (print == -1)
	{
	  const char *msgverb_var = getenv ("MSGVERB");
	  const char *sevlevel_var = getenv ("SEV_LEVEL");

	  if (msgverb_var != NULL && msgverb_var[0] != '\0')
	    {
	      /* Using this extra variable allows us to work without
		 locking.  */
	      print = 0;

	      do
		{
		  size_t cnt;

		  for (cnt = 0; cnt < NKEYWORDS; ++cnt)
		    if (memcmp (msgverb_var,
				keywords[cnt].name, keywords[cnt].len) == 0
			&& (msgverb_var[keywords[cnt].len] == ':'
			    || msgverb_var[keywords[cnt].len] == '\0'))
		      break;

		  if (cnt < NKEYWORDS)
		    {
		      print |= 1 << cnt;

		      msgverb_var += keywords[cnt].len;
		      if (msgverb_var[0] == ':')
			++msgverb_var;
		    }
		  else
		    {
		     /* We found an illegal keyword in the
			environment variable.  The specifications say
			that we print all fields.  */
		      print = all_mask;
		      break;
		    }
		}
	      while (msgverb_var[0] != '\0');
	    }
	  else
	    print = all_mask;


	  if (sevlevel_var != NULL)
	    while (sevlevel_var[0] != '\0')
	      {
		const char *end = strchr (sevlevel_var, ':');
		int level;

		if (end == NULL)
		  end = strchr (sevlevel_var, '\0');

		/* First field: keyword.  This is not used here but it
		   must be present.  */
		while (sevlevel_var < end)
		  if (*sevlevel_var++ == ',')
		    break;

		if (sevlevel_var < end)
		  {
		    /* Second field: severity level, a number.  */
		    char *cp;

		    level = strtol (sevlevel_var, &cp, 0);
		    if (cp != sevlevel_var && cp < end && *cp++ == ','
			&& level > MM_INFO)
		      {
			const char *new_string;

			new_string = __strndup (cp, end - cp);

			if (new_string != NULL
			    && (internal_addseverity (level, new_string)
				!= MM_OK))
			  free ((char *) new_string);
		      }
		  }

		sevlevel_var = end + (*end == ':' ? 1 : 0);
	      }
	}

      __libc_lock_unlock (lock);
    }

  /* Start the real work.  First check whether the input is ok.  */
  if (label != MM_NULLLBL)
    {
      /* Must be two fields, separated by a colon.  */
      const char *cp = strchr (label, ':');
      if (cp == NULL)
	return MM_NOTOK;

      /* The first field must not contain more then 10 bytes.  */
      if (cp - label > 10
	  /* The second field must not have more then 14 bytes.  */
	  || strlen (cp + 1) > 14)
	return MM_NOTOK;
    }

  for (severity_rec = severity_list; severity_rec != NULL;
       severity_rec = severity_rec->next)
    if (severity == severity_rec->severity)
      /* Bingo.  */
      break;

  /* If we don't know anything about the severity level return an error.  */
  if (severity_rec == NULL)
    return MM_NOTOK;


  /* Now we can print.  */
  if (classification & MM_PRINT)
    {
      int do_label = (print & label_mask) && label != MM_NULLLBL;
      int do_severity = (print & severity_mask) && severity != MM_NULLSEV;
      int do_text = (print & text_mask) && text != MM_NULLTXT;
      int do_action = (print & action_mask) && action != MM_NULLACT;
      int do_tag = (print & tag_mask) && tag != MM_NULLTAG;

      if (fprintf (stderr, "%s%s%s%s%s%s%s%s%s%s\n",
		   do_label ? label : "",
		   do_label && (do_severity | do_text) ? ": " : "",
		   do_severity ? severity_rec->string : "",
		   do_severity && do_text ? ": " : "",
		   do_text ? text : "",
		   (do_label | do_severity | do_text) && (do_action | do_tag)
		   ? "\n" : "",
		   do_action ? "TO FIX: " : "",
		   do_action ? action : "",
		   do_action && do_tag ? " " : "",
		   do_tag ? tag : "") == EOF)
	/* Oh, oh.  An error occured during the output.  */
	result = MM_NOMSG;
    }

  if (classification & MM_CONSOLE)
    {
      int do_label = label != MM_NULLLBL;
      int do_severity = severity != MM_NULLSEV;
      int do_text = text != MM_NULLTXT;
      int do_action = action != MM_NULLACT;
      int do_tag = tag != MM_NULLTAG;

      syslog (LOG_ERR, "%s%s%s%s%s%s%s%s%s%s\n",
	      do_label ? label : "",
	      do_label && (do_severity | do_text) ? ": " : "",
	      do_severity ? severity_rec->string : "",
	      do_severity && do_text ? ": " : "",
	      do_text ? text : "",
	      (do_label | do_severity | do_text) && (do_action | do_tag)
	      ? "\n" : "",
	      do_action ? "TO FIX: " : "",
	      do_action ? action : "",
	      do_action && do_tag ? " " : "",
	      do_tag ? tag : "");
    }

  return result;
}


/* Add the new entry to the list.  */
static int
internal_addseverity (int severity, const char *string)
{
  struct severity_info *runp, *lastp;
  int result = MM_OK;

  /* First see if there is already a record for the severity level.  */
  for (runp = severity_list, lastp = NULL; runp != NULL; runp = runp-> next)
    if (runp->severity == severity)
      break;
    else
      lastp = runp;

  if (runp != NULL)
    {
      /* Release old string.  */
      free ((char *) runp->string);

      if (string != NULL)
	/* Change the string.  */
	runp->string = string;
      else
	{
	  /* Remove the severity class.  */
	  if (lastp == NULL)
	    severity_list = runp->next;
	  else
	    lastp->next = runp->next;

	  free (runp);
	}
    }
  else if (string != NULL)
    {
      runp = malloc (sizeof (*runp));
      if (runp == NULL)
	result = MM_NOTOK;
      else
	{
	  runp->severity = severity;
	  runp->next = severity_list;
	  runp->string = string;
	  severity_list = runp;
	}
    }
  else
    /* We tried to remove a non-existing severity class.  */
    result = MM_NOTOK;

  return result;
}


/* Add new severity level or remove old one.  */
int
addseverity (int severity, const char *string)
{
  int result;
  const char *new_string;

  if (string == NULL)
    /* We want to remove the severity class.  */
    new_string = NULL;
  else
    {
      new_string = __strdup (string);

      if (new_string == NULL || severity <= MM_INFO)
	/* Allocation failed or illegal value.  */
	return MM_NOTOK;
    }

  /* Protect the global data.  */
  __libc_lock_lock (lock);

  /* Do the real work.  */
  result = internal_addseverity (severity, string);

  if (result != MM_OK)
    /* Free the allocated string.  */
    free ((char *) new_string);

  /* Release the lock.  */
  __libc_lock_unlock (lock);

  return result;
}
