/* Copyright (C) 1996 Free Software Foundation, Inc.
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
not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#ifndef _NSSWITCH_H
#define _NSSWITCH_H	1

/* This is an *internal* header.  */

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <search.h>


/* Revision number of NSS interface (must be a string).  */
#define NSS_SHLIB_REVISION ".1"


/* Possible results of lookup using a nss_* function.  */
enum nss_status
{
  NSS_STATUS_TRYAGAIN = -2,
  NSS_STATUS_UNAVAIL,
  NSS_STATUS_NOTFOUND,
  NSS_STATUS_SUCCESS,
};


/* Actions performed after lookup finished.  */
typedef enum
{
  NSS_ACTION_CONTINUE,
  NSS_ACTION_RETURN
} lookup_actions;


typedef struct service_library
{
  /* Name of service (`files', `dns', `nis', ...).  */
  const char *name;
  /* Pointer to the loaded shared library.  */
  void *lib_handle;
  /* And the link to the next entry.  */
  struct service_library *next;
} service_library;


/* For mappng a function name to a function pointer.  */
typedef struct
{
  const char *fct_name;
  void *fct_ptr;
} known_function;


typedef struct service_user
{
  /* Name of the service (`files', `dns', `nis', ...).  */
  const char *name;
  /* Action according to result.  */
  lookup_actions actions[4];
  /* Link to the underlying library object.  */
  service_library *library;
  /* Collection of known functions.  */
  struct entry *known;
  /* And the link to the next entry.  */
  struct service_user *next;
} service_user;

/* To access the action based on the status value use this macro.  */
#define nss_next_action(ni, status) ((ni)->actions[2 + status])


typedef struct name_database_entry
{
  /* Name of the database.  */
  const char *name;
  /* List of service to be used.  */
  service_user *service;
  /* And the link to the next entry.  */
  struct name_database_entry *next;
} name_database_entry;


typedef struct name_database
{
  /* List of all known databases.  */
  name_database_entry *entry;
  /* List of libraries with service implementation.  */
  service_library *library;
} name_database;


/* Interface functions for NSS.  */

/* Get the data structure representing the specified database.
   If there is no configuration for this database in the file,
   parse a service list from DEFCONFIG and use that.  More
   than one function can use the database.  */
int __nss_database_lookup (const char *database, const char *defconfig,
			   service_user **ni);


/* Put first function with name FCT_NAME for SERVICE in FCTP.  The
   position is remembered in NI.  The function returns a value < 0 if
   an error occured or no such function exists.  */
int __nss_lookup (service_user **ni, const char *fct_name, void **fctp);

/* Determine the next step in the lookup process according to the
   result STATUS of the call to the last function returned by
   `__nss_lookup' or `__nss_next'.  NI specifies the last function
   examined.  The function return a value > 0 if the process should
   stop with the last result of the last function call to be the
   result of the entire lookup.  The returned valie is 0 if there is
   another function to use and < 0 if an error occured.

   If ALL_VALUES is nonzero, the return value will not be > 0 as long as
   there is a possibility the lookup process can ever use following
   services.  In other words, only if all four lookup results have
   the action RETURN associated the lookup process stops before the
   natural end.  */
int __nss_next (service_user **ni, const char *fct_name, void **fctp,
		int status, int all_values);


#endif	/* nsswitch.h */
