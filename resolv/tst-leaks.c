/* Tests for res_query in libresolv
   Copyright (C) 2003 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <mcheck.h>

/* Prototype for our test function.  */
extern int do_test (int argc, char *argv[]);

/* This defines the `main' function and some more.  */
#include <test-skeleton.c>

int
do_test (int argc, char *argv[])
{
  unsigned char buf[256];

  mtrace();

  /* This will allocate some memory, which should be automatically
     freed at exit.  */
  res_query ("1.0.0.127.in-addr.arpa.", C_ANY, T_ANY, buf, 256);

  return 0;
}
