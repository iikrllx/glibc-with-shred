/* Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

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

#include <stdlib.h>
#include "pthreadP.h"
#include <shlib-compat.h>


#if SHLIB_COMPAT(libpthread, GLIBC_2_0, GLIBC_2_3_2)
int
__old_pthread_cond_destroy (cond)
     pthread_cond_t *cond;
{
  /* Free the memory which was eventually allocated.  */
  free (*(void **) cond);

  return 0;
}
compat_symbol (libpthread, __old_pthread_cond_destroy, pthread_cond_destroy,
	       GLIBC_2_0);
#endif
