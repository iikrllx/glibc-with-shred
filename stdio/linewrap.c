/* Word-wrapping and line-truncating streams.
Copyright (C) 1996 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/* We keep this data for each line-wrapping stream.  */

struct data
  {
    const size_t *lmargin, *rmargin; /* Left and right margins.  */
    const size_t *wrapmargin;	/* Margin to wrap to, or null to truncate.  */
    size_t point;		/* Current column of last chars flushed.  */

    /* Original cookie and hooks from the stream.  */
    void *cookie;
    void (*output) (FILE *, int);
    __io_close_fn *close;
    __io_fileno_fn *fileno;
    __io_seek_fn *seek;
  };

/* Install our hooks into a stream.  */

static inline void
wrap_stream (FILE *stream, struct data *d)
{
  static void lwoutput (FILE *, int);
  static __io_close_fn lwclose;
  static __io_fileno_fn lwfileno;

  stream->__cookie = d;
  stream->__room_funcs.__output = &lwoutput;
  stream->__io_funcs.__close = &lwclose;
  stream->__io_funcs.__fileno = &lwfileno;
  stream->__io_funcs.__seek = NULL; /* Cannot seek.  */
}

/* Restore a stream to its original state.  */

static inline void
unwrap_stream (FILE *stream, struct data *d)
{
  stream->__cookie = d->cookie;
  stream->__room_funcs.__output = d->output;
  stream->__io_funcs.__close = d->close;
  stream->__io_funcs.__fileno = d->fileno;
  stream->__io_funcs.__seek = d->seek;
}

/* Cookie io functions that might get called on a wrapped stream.
   Must pass the original cookie to the original functions.  */

static int
lwclose (void *cookie)
{
  struct data *d = cookie;
  return (*d->close) (d->cookie);
}

static int
lwfileno (void *cookie)
{
  struct data *d = cookie;
  return (*d->fileno) (d->cookie);
}

/* This function is called when STREAM must be flushed.
   C is EOF or a character to be appended to the buffer contents.  */

static void
lwoutput (FILE *stream, int c)
{
  char *buf, *nl;
  size_t len;

  /* Extract our data and restore the stream's original cookie
     and output function so writes we do really go out.  */
  struct data *d = stream->__cookie;
  unwrap_stream (stream, d);

  /* Scan the buffer for newlines.  */
  for (buf = stream->__buffer;
       (buf < stream->__bufp || (c != EOF && c != '\n')) && !stream->__error)
    {
      size_t r;

      if (d->point == 0 && d->lmargin && *d->lmargin != 0)
	{
	  /* We are starting a new line.  Print spaces to the left margin.  */
	  const size_t pad = *d->lmargin;
	  if (stream->__bufp + pad < stream->__put_limit)
	    {
	      /* We can fit in them in the buffer by moving the
		 buffer text up and filling in the beginning.  */
	      memmove (buf + pad, buf, stream->__bufp - buf);
	      stream->__bufp += pad; /* Compensate for bigger buffer. */
	      memset (buf, ' ', pad); /* Fill in the spaces.  */
	      buf += pad; /* Don't bother searching them.  */
	    }
	  else
	    {
	      /* No buffer space for spaces.  Must flush.  */
	      size_t i;
	      char *olimit;

	      len = stream->__bufp - buf;
	      olimit = stream->__put_limit;
	      stream->__bufp = stream->__put_limit = buf;
	      for (i = 0; i < pad; ++i)
		(*d->output) (stream, ' ');
	      stream->__put_limit = olimit;
	      memcpy (stream->__bufp, buf, len);
	      stream->__bufp += len;
	    }
	  d->point = pad;
	}

      len = stream->__bufp - buf;
      nl = memchr (buf, '\n', len);

      if (!nl)
	{
	  /* The buffer ends in a partial line.  */

	  if (!d->rmargin ||
	      d->point + len + (c != EOF && c != '\n') <= d->rmargin)
	    {
	      /* The remaining buffer text is a partial line and fits
		 within the maximum line width.  Advance point for the
		 characters to be written and stop scanning.  */
	      d->point += len;
	      break;
	    }
	  else
	    /* Set the end-of-line pointer for the code below to
	       the end of the buffer.  */
	    nl = stream->__bufp;
	}
      else if (!d->rmargin || d->point + (nl - buf) <= d->rmargin)
	{
	  /* The buffer contains a full line that fits within the maximum
	     line width.  Reset point and scan the next line.  */
	  d->point = 0;
	  buf = nl + 1;
	  continue;
	}

      /* This line is too long.  */
      r = *d->rmargin;

      if (! d->wrapmargin)
	{
	  /* Truncate the line by overwriting the excess with the
	     newline and anything after it in the buffer.  */
	  if (nl < stream->__bufp)
	    {
	      memcpy (buf + (r - d->point), nl, stream->__bufp - nl);
	      stream->__bufp -= buf + (r - d->point) - nl;
	      /* Reset point for the next line and start scanning it.  */
	      d->point = 0;
	      buf += r + 1; /* Skip full line plus \n. */
	    }
	  else
	    {
	      /* The buffer ends with a partial line that is beyond the
		 maximum line width.  Advance point for the characters
		 written, and discard those past the max from the buffer.  */
	      d->point += len;
	      stream->__bufp -= d->point - r;
	      if (c != '\n')
		/* Swallow the extra character too.  */
		c = EOF;
	      break;
	    }
	}
      else
	{
	  /* Do word wrap.  Go to the column just past the maximum line
	     width and scan back for the beginning of the word there.
	     Then insert a line break.  */

	  char *p, *nextline;
	  int i;

	  p = buf + (r + 1 - d->point);
	  while (p >= buf && !isblank (*p))
	    --p;
	  nextline = p + 1;	/* This will begin the next line.  */

	  if (nextline > buf)
	    {
	      /* Swallow separating blanks.  */
	      do
		--p;
	      while (isblank (*p));
	      nl = p + 1;	/* The newline will replace the first blank. */
	    }
	  else
	    {
	      /* A single word that is greater than the maximum line width.
		 Oh well.  Put it on an overlong line by itself.  */
	      p = buf + (r + 1 - d->point);
	      /* Find the end of the long word.  */
	      do
		++p;
	      while (p < nl && !isblank (*p));
	      if (p == nl)
		{
		  /* It already ends a line.  No fussing required.  */
		  d->point = 0;
		  buf = nl + 1;
		  continue;
		}
	      /* We will move the newline to replace the first blank.  */
	      nl = p;
	      /* Swallow separating blanks.  */
	      do
		++p;
	      while (isblank (*p));
	      /* The next line will start here.  */
	      nextline = p;
	    }

	  /* Temporarily reset bufp to include just the first line.  */
	  stream->__bufp = nl;
	  if (nextline - (nl + 1) < d->wrap)
	    /* The margin needs more blanks than we removed.
	       Output the first line so we can use the space.  */
	    (*d->output) (stream, '\n');
	  else
	    /* We can fit the newline and blanks in before
	       the next word.  */
	    *stream->__bufp++ = '\n';

	  /* Reset the counter of what has been output this line.  */
	  d->point = 0;

	  /* Add blanks up to the wrap margin column.  */
	  for (i = 0; i < d->wrap; ++i)
	    *stream->__bufp++ = ' ';

	  /* Copy the tail of the original buffer into the current buffer
	     position.  */
	  if (stream->__bufp != nextline)
	    memcpy (stream->__bufp, nextline, buf + len - nextline);
	  len -= nextline - buf;

	  /* Continue the scan on the remaining lines in the buffer.  */
	  buf = stream->__bufp;

	  /* Restore bufp to include all the remaining text.  */
	  stream->__bufp += len;
	}
    }

  if (!stream->__error)
    {
      (*d->output) (stream, c);
      if (c == '\n')
	d->point = 0;
      else if (c != EOF)
	++d->point;
    }

  wrap_stream (stream, d);
}

/* Modify STREAM so that it prefixes lines written on it with *LMARGIN
   spaces and limits them to *RMARGIN columns total.  If WRAP is not null,
   words that extend past *RMARGIN are wrapped by replacing the whitespace
   before them with a newline and *WRAP spaces.  Otherwise, chars beyond
   *RMARGIN are simply dropped until a newline.  Returns STREAM after
   modifying it, or NULL if there was an error.  The pointers passed are
   stored in the stream and so must remain valid until `line_unwrap_stream'
   is called; the values pointed to can be changed between stdio calls.  */

FILE *
line_wrap_stream (FILE *stream, size_t *lmargin, size_t *rmargin, size_t *wrap)
{
  struct data *d = malloc (sizeof *d);

  if (!d)
    return NULL;

  /* Ensure full setup before we start tweaking.  */
  fflush (stream);

  /* Initialize our wrapping state.  */
  d->point = 0;

  /* Save the original cookie and output and close hooks.  */
  d->cookie = stream->__cookie;
  d->output = stream->__room_funcs.__output;
  d->close = stream->__io_funcs.__close;
  d->fileno = stream->__io_funcs.__fileno;

  /* Take over the stream.  */
  wrap_stream (stream, d);

  /* Line-wrapping streams are normally line-buffered.  This is not
     required, just assumed desired.  The wrapping feature should continue
     to work if the stream is switched to full or no buffering.  */
  stream->__linebuf = 1;

#define	ref(arg)	d->arg = arg
  ref (lmargin);
  ref (rmargin);
  ref (wrap);
#undef	ref

  return stream;
}

/* Remove the hooks placed in STREAM by `line_wrap_stream'.  */

void
line_unwrap_stream (FILE *stream)
{
  struct data *d = stream->__cookie;
  unwrap_stream (stream, d);
  free (d);
}

#ifdef TEST
int
main (int argc, char **argv)
{
  int c;
  puts ("stopme");
  line_wrap_stream (stdout, atoi (argv[1]), atoi (argv[2] ?: "-1"));
  while ((c = getchar()) != EOF) putchar (c);
  return 0;
}
#endif
