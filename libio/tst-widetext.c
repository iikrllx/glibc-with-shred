/* Test program for the wide character stream functions handling larger
   amounts of text.
   Copyright (C) 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>.

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

#include <assert.h>
#include <iconv.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

/* Approximate size of the file (must be larger).  */
#define SIZE 210000


int
main (void)
{
  char name[] = "/tmp/widetext.out.XXXXXX";
  char mbbuf[SIZE];
  char mb2buf[SIZE];
  wchar_t wcbuf[SIZE];
  wchar_t wc2buf[SIZE];
  size_t mbsize;
  size_t wcsize;
  int fd;
  FILE *fp;
  size_t n;
  int res;
  int status = 0;
  wchar_t *wcp;

  setlocale (LC_ALL, "de_DE.UTF-8");
  printf ("locale used: %s\n\n", setlocale (LC_ALL, NULL));

  /* Read the file into memory.  */
  mbsize = fread (mbbuf, 1, SIZE, stdin);
  if (mbsize == 0)
    {
      printf ("%Zd: cannot read input file from standard input: %m\n",
	      __LINE__);
      exit (1);
    }

   printf ("INFO: input file has %Zd bytes\n", mbsize);

  /* First convert the text to wide characters.  We use iconv here.  */
  {
    iconv_t cd;
    char *inbuf = mbbuf;
    size_t inleft = mbsize;
    char *outbuf = (char *) wcbuf;
    size_t outleft = sizeof (wcbuf);
    size_t nonr;

    cd = iconv_open ("WCHAR_T", "UTF-8");
    if (cd == (iconv_t) -1)
      {
	printf ("%Zd: cannot get iconv descriptor for conversion to UCS4\n",
		__LINE__);
	exit (1);
      }

    /* We must need only one call and there must be no losses.  */
    nonr = iconv (cd, &inbuf, &inleft, &outbuf, &outleft);
    if (nonr != 0 && nonr != (size_t) -1)
      {
	printf ("%Zd: iconv performed %Zd nonreversible conversions\n",
		__LINE__, nonr);
	exit (1);
      }

    if  ((size_t) nonr == -1 )
      {
	printf ("\
%Zd: iconv returned with %Zd and errno = %m (inleft: %Zd, outleft: %Zd)\n",
		__LINE__, nonr, inleft, outleft);
	exit (1);
      }

    if (inleft != 0)
      {
	printf ("%Zd: iconv didn't convert all input\n", __LINE__);
	exit (1);
      }

    iconv_close (cd);

    if ((sizeof (wcbuf) - outleft) % sizeof (wchar_t) != 0)
      {
	printf ("%Zd: iconv converted not complete wchar_t\n", __LINE__);
	exit (1);
      }

    wcsize = (sizeof (wcbuf) - outleft) / sizeof (wchar_t);
    assert (wcsize + 1 <= SIZE);
  }

  /* Now that we finished the preparations, run the first test.  We
     are writing the wide char data out and read it back in.  We write
     and read single characters.  */

  fd = mkstemp (name);
  if (fd == -1)
    {
      printf ("%Zd: cannot open temporary file: %m\n", __LINE__);
      exit (1);
    }

  unlink (name);

  fp = fdopen (dup (fd), "w");
  if (fp == NULL)
    {
      printf ("%Zd: fdopen of temp file for writing failed: %m\n", __LINE__);
      exit (1);
    }

  for (n = 0; n < wcsize; ++n)
    {
      if (fputwc (wcbuf[n], fp) == WEOF)
	{
	  printf ("%Zd: fputwc failed: %m\n", __LINE__);
	  exit (1);
	}
    }

  res = fclose (fp);
  if (res != 0)
    {
      printf ("%Zd: fclose after single-character writing failed (%d): %m\n",
	      __LINE__, res);
      exit (1);
    }

  lseek (fd, SEEK_SET, 0);
  fp = fdopen (dup (fd), "r");
  if (fp == NULL)
    {
      printf ("%Zd: fdopen of temp file for reading failed: %m\n", __LINE__);
      exit (1);
    }

  for (n = 0; n < wcsize; ++n)
    {
      wint_t wch = fgetwc (fp);
      if (wch == WEOF)
	{
	  printf ("%Zd: fgetwc failed (idx %Zd): %m\n", __LINE__, n);
	  exit (1);
	}
      wc2buf[n] = wch;
    }

  /* There should be nothing else.  */
  if (fgetwc (fp) != WEOF)
    {
      printf ("%Zd: too many characters available with fgetwc\n", __LINE__);
      status = 1;
    }
  else if (wmemcmp (wcbuf, wc2buf, wcsize) != 0)
    {
      printf ("%Zd: buffer read with fgetwc differs\n", __LINE__);
      status = 1;
    }

  res = fclose (fp);
  if (res != 0)
    {
      printf ("%Zd: fclose after single-character reading failed (%d): %m\n",
	      __LINE__, res);
      exit (1);
    }

  /* Just make sure there are no two errors which hide each other, read the
     file using the `char' functions.  */

  lseek (fd, SEEK_SET, 0);
  fp = fdopen (fd, "r");
  if (fp == NULL)
    {
      printf ("%Zd: fdopen of temp file for reading failed: %m\n", __LINE__);
      exit (1);
    }

  if (fread (mb2buf, 1, mbsize, fp) != mbsize)
    {
      printf ("%Zd: cannot read all of the temp file\n", __LINE__);
      status = 1;
    }
  else
    {
      /* Make sure there is nothing left.  */
      if (fgetc (fp) != EOF)
	{
	  printf ("%Zd: more input avilable", __LINE__);
	  status = 1;
	}

      if (memcmp (mb2buf, mbbuf, mbsize) != 0)
	{
	  printf ("%Zd: buffer written with fputwc differs\n", __LINE__);
	  status = 1;
	}
    }

  res = fclose (fp);
  if (res != 0)
    {
      printf ("%Zd: fclose after single-character reading failed (%d): %m\n",
	      __LINE__, res);
      exit (1);
    }

  /* Now to reading and writing line-wise.  */

  fd = mkstemp (strcpy (name, "/tmp/widetext.out.XXXXXX"));
  if (fd == -1)
    {
      printf ("%Zd: cannot open temporary file: %m\n", __LINE__);
      exit (1);
    }

  unlink (name);

  fp = fdopen (dup (fd), "w");
  if (fp == NULL)
    {
      printf ("%Zd: fdopen of temp file for writing failed: %m\n", __LINE__);
      exit (1);
    }

  for (wcp = wcbuf; wcp < &wcbuf[wcsize]; )
    {
      wchar_t *wendp = wcschr (wcp, L'\n');

      if (wendp != NULL)
	{
	  /* Temporarily NUL terminate the line.  */
	  wchar_t save = wendp[1];
	  wendp[1] = L'\0';

	  fputws (wcp, fp);

	  wendp[1] = save;
	  wcp = &wendp[1];
	}
      else
	{
	  fputws (wcp, fp);
	  wcp = wcschr (wcp, L'\0');
	  assert (wcp == &wcbuf[wcsize]);
	}
    }

  res = fclose (fp);
  if (res != 0)
    {
      printf ("%Zd: fclose after line-wise writing failed (%d): %m\n",
	      __LINE__, res);
      exit (1);
    }

  lseek (fd, SEEK_SET, 0);
  fp = fdopen (dup (fd), "r");
  if (fp == NULL)
    {
      printf ("%Zd: fdopen of temp file for reading failed: %m\n", __LINE__);
      exit (1);
    }

  for (wcp = wc2buf; wcp < &wc2buf[wcsize]; )
    {
      if (fgetws (wcp, &wc2buf[wcsize] - wcp + 1, fp) == NULL)
	{
	  printf ("%Zd: short read using fgetws (only %Zd of %Zd)\n",
		  __LINE__, wcp - wc2buf, wcsize);
	  status = 1;
	  break;
	}
      wcp = wcschr (wcp, L'\0');
    }

  if (wcp > &wc2buf[wcsize])
    {
      printf ("%Zd: fgetws read too much\n", __LINE__);
      status = 1;
    }
  else if (fgetwc (fp) != WEOF)
    {
      /* There should be nothing else.  */
      printf ("%Zd: too many characters available with fgetws\n", __LINE__);
      status = 1;
    }

  if (wcp >= &wc2buf[wcsize] && wmemcmp (wcbuf, wc2buf, wcsize) != 0)
    {
      printf ("%Zd: buffer read with fgetws differs\n", __LINE__);
      status = 1;
    }

  res = fclose (fp);
  if (res != 0)
    {
      printf ("%Zd: fclose after single-character reading failed (%d): %m\n",
	      __LINE__, res);
      exit (1);
    }

  /* Just make sure there are no two errors which hide each other, read the
     file using the `char' functions.  */

  lseek (fd, SEEK_SET, 0);
  fp = fdopen (fd, "r");
  if (fp == NULL)
    {
      printf ("%Zd: fdopen of temp file for reading failed: %m\n", __LINE__);
      exit (1);
    }

  if (fread (mb2buf, 1, mbsize, fp) != mbsize)
    {
      printf ("%Zd: cannot read all of the temp file\n", __LINE__);
      status = 1;
    }
  else
    {
      /* Make sure there is nothing left.  */
      if (fgetc (fp) != EOF)
	{
	  printf ("%Zd: more input avilable", __LINE__);
	  status = 1;
	}

      if (memcmp (mb2buf, mbbuf, mbsize) != 0)
	{
	  printf ("%Zd: buffer written with fputws differs\n", __LINE__);
	  status = 1;
	}
    }

  res = fclose (fp);
  if (res != 0)
    {
      printf ("%Zd: fclose after single-character reading failed (%d): %m\n",
	      __LINE__, res);
      exit (1);
    }

  return status;
}
