/* Tests for loading and unloading of iconv modules.
   Copyright (C) 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 2000.

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

#include <iconv.h>
#include <mcheck.h>
#include <stdio.h>
#include <stdlib.h>


/* How many load/unload operations do we do.  */
#define TEST_ROUNDS	5000


enum state { unloaded, loaded };

struct
{
  const char *name;
  enum state state;
  iconv_t cd;
} modules[] =
{
#define MODULE(Name) { .name = #Name, .state = unloaded }
  MODULE (ISO-8859-1),
  MODULE (ISO-8859-2),
  MODULE (ISO-8859-3),
  MODULE (ISO-8859-4),
  MODULE (ISO-8859-5),
  MODULE (ISO-8859-6),
  MODULE (ISO-8859-15),
  MODULE (EUC-JP),
  MODULE (EUC-KR),
  MODULE (EUC-CN),
  MODULE (EUC-TW),
  MODULE (SJIS),
  MODULE (UHC),
  MODULE (KOI8-R),
  MODULE (BIG5),
  MODULE (BIG5HKSCS)
};
#define nmodules (sizeof (modules) / sizeof (modules[0]))


/* The test data.  */
static const char inbuf[] = "\
The first step is the function to create a handle.

 - Function: iconv_t iconv_open (const char *TOCODE, const char
          *FROMCODE)
     The `iconv_open' function has to be used before starting a
     conversion.  The two parameters this function takes determine the
     source and destination character set for the conversion and if the
     implementation has the possibility to perform such a conversion the
     function returns a handle.

     If the wanted conversion is not available the function returns
     `(iconv_t) -1'.  In this case the global variable `errno' can have
     the following values:

    `EMFILE'
          The process already has `OPEN_MAX' file descriptors open.

    `ENFILE'
          The system limit of open file is reached.

    `ENOMEM'
          Not enough memory to carry out the operation.

    `EINVAL'
          The conversion from FROMCODE to TOCODE is not supported.

     It is not possible to use the same descriptor in different threads
     to perform independent conversions.  Within the data structures
     associated with the descriptor there is information about the
     conversion state.  This must not be messed up by using it in
     different conversions.

     An `iconv' descriptor is like a file descriptor as for every use a
     new descriptor must be created.  The descriptor does not stand for
     all of the conversions from FROMSET to TOSET.

     The GNU C library implementation of `iconv_open' has one
     significant extension to other implementations.  To ease the
     extension of the set of available conversions the implementation
     allows storing the necessary files with data and code in
     arbitrarily many directories.  How this extension has to be
     written will be explained below (*note glibc iconv
     Implementation::).  Here it is only important to say that all
     directories mentioned in the `GCONV_PATH' environment variable are
     considered if they contain a file `gconv-modules'.  These
     directories need not necessarily be created by the system
     administrator.  In fact, this extension is introduced to help users
     writing and using their own, new conversions.  Of course this does
     not work for security reasons in SUID binaries; in this case only
     the system directory is considered and this normally is
     `PREFIX/lib/gconv'.  The `GCONV_PATH' environment variable is
     examined exactly once at the first call of the `iconv_open'
     function.  Later modifications of the variable have no effect.
";


int
main (void)
{
  int count = TEST_ROUNDS;
  int result = 0;

  mtrace ();

  /* Just a seed.  */
  srandom (TEST_ROUNDS);

  while (count--)
    {
      int idx = random () % nmodules;

      if (modules[idx].state == unloaded)
	{
	  char outbuf[10000];
	  char *inptr = (char *) inbuf;
	  size_t insize = sizeof (inbuf) - 1;
	  char *outptr = outbuf;
	  size_t outsize = sizeof (outbuf);

	  /* Load the module and do the conversion.  */
	  modules[idx].cd = iconv_open ("UTF-8", modules[idx].name);

	  if (modules[idx].cd == (iconv_t) -1)
	    {
	      printf ("opening of %s failed: %m\n", modules[idx].name);
	      result = 1;
	      break;
	    }

	  modules[idx].state = loaded;

	  /* Now a simple test.  */
	  if (iconv (modules[idx].cd, &inptr, &insize, &outptr, &outsize) != 0
	      || *inptr != '\0')
	    {
	      printf ("conversion with %s failed\n", modules[idx].name);
	      result = 1;
	    }
	}
      else
	{
	  /* Unload the module.  */
	  if (iconv_close (modules[idx].cd) != 0)
	    {
	      printf ("closing of %s failed: %m\n", modules[idx].name);
	      result = 1;
	      break;
	    }

	  modules[idx].state = unloaded;
	}
    }

  for (count = 0; count < nmodules; ++count)
    if (modules[count].state == loaded && iconv_close (modules[count].cd) != 0)
      {
	printf ("closing of %s failed: %m\n", modules[count].name);
	result = 1;
      }

  return result;
}
