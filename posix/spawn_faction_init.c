/* Copyright (C) 2000 Free Software Foundation, Inc.
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

#include <errno.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>


/* Function used to increase the size of the allocated array.  This
   function is called from the `add'-functions.  */
int
__posix_spawn_file_actions_realloc (posix_spawn_file_actions_t *file_actions)
{
  void *newmem = realloc (file_actions->__actions,
			  file_actions->__allocated += 8);

  if (newmem == NULL)
    {
      /* Not enough memory.  */
      file_actions->__allocated -= 8;
      return ENOMEM;
    }

  file_actions->__actions = (struct __spawn_action *) newmem;

  return 0;
}


/* Initialize data structure for file attribute for `spawn' call.  */
int
posix_spawn_file_actions_init (posix_spawn_file_actions_t *file_actions)
{
  /* Simply clear all the elements.  */
  memset (file_actions, '\0', sizeof (*file_actions));
  return 0;
}
