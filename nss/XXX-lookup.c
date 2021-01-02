/* Copyright (C) 1996-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.

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
   <https://www.gnu.org/licenses/>.  */

#include "nsswitch.h"

/*******************************************************************\
|* Here we assume one symbol to be defined:			   *|
|* 								   *|
|* DATABASE_NAME - name of the database the function accesses	   *|
|*		   (e.g., hosts, services, ...)			   *|
|* 								   *|
|* One additional symbol may optionally be defined:		   *|
|* 								   *|
|* ALTERNATE_NAME - name of another service which is examined in   *|
|*                  case DATABASE_NAME is not found                *|
|* 								   *|
|* DEFAULT_CONFIG - string for default conf (e.g. "dns files")	   *|
|* 								   *|
\*******************************************************************/

#define DB_LOOKUP_FCT CONCAT3_1 (__nss_, DATABASE_NAME, _lookup2)
#define CONCAT3_1(Pre, Name, Post) CONCAT3_2 (Pre, Name, Post)
#define CONCAT3_2(Pre, Name, Post) Pre##Name##Post

#define DATABASE_NAME_SYMBOL CONCAT3_1 (__nss_, DATABASE_NAME, _database)
#define DATABASE_NAME_STRING STRINGIFY1 (DATABASE_NAME)
#define STRINGIFY1(Name) STRINGIFY2 (Name)
#define STRINGIFY2(Name) #Name

#ifdef ALTERNATE_NAME
#define ALTERNATE_NAME_STRING STRINGIFY1 (ALTERNATE_NAME)
#else
#define ALTERNATE_NAME_STRING NULL
#endif

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG NULL
#endif

int
DB_LOOKUP_FCT (nss_action_list *ni, const char *fct_name, const char *fct2_name,
	       void **fctp)
{
  if (__nss_database_lookup2 (DATABASE_NAME_STRING, ALTERNATE_NAME_STRING,
			      DEFAULT_CONFIG, &DATABASE_NAME_SYMBOL) < 0)
    return -1;

  *ni = DATABASE_NAME_SYMBOL;

  return __nss_lookup (ni, fct_name, fct2_name, fctp);
}
libc_hidden_def (DB_LOOKUP_FCT)
