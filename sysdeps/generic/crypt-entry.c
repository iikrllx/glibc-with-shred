/* crypt - wrapper aroung MD5 sum replacement for crypt function.
Copyright (C) 1996 Free Software Foundation, Inc.
This file is part of the GNU C Library.
Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <crypt.h>
#include <errno.h>
#include <string.h>


/* Define our magic string to mark salt for MD5 encryption
   replacement.  This is meant to be the same as for other MD5 based
   encryption implenentations.  */
static const char md5_salt_prefix[] = "$1$";


/* Prototypes for the MD5 encryption replacement functions.  */
extern char *md5_crypt_r (const char *key, const char *salt, char *buffer,
			  int buflen);
extern char *md5_crpyt (const char *key, const char *salt);


/* We recognize an intended call of the MD5 crypt replacement function
   by the first 3 characters of the salt string.  If they match the
   MD5 magic string we want MD5 encryption replacement.  */
char *
crypt_r (key, salt, data)
     const char *key;
     const char *salt;
     struct crypt_data *data;
{
  if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0)
    return md5_crypt_r (key, salt, (char *) data, sizeof (struct crypt_data));

  /* We don't have DES encryption.  */
  errno = ENOSYS;
  return NULL;
}


/* The same here, only we call the non-reentrant version.  */
char *
crypt (key, salt)
     const char *key;
     const char *salt;
{
  if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0)
    return md5_crypt (key, salt);

  /* We don't have DES encryption.  */
  errno = ENOSYS;
  return NULL;
}
