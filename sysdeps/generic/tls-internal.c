/* Per-thread state.  Generic version.
   Copyright (C) 2020-2022 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <stdlib/arc4random.h>
#include <string.h>
#include <tls-internal.h>

__thread struct tls_internal_t __tls_internal;

void
__glibc_tls_internal_free (void)
{
  free (__tls_internal.strsignal_buf);
  free (__tls_internal.strerror_l_buf);

  if (__tls_internal.rand_state != NULL)
    {
      /* Clear any lingering random state prior so if the thread stack is
	 cached it won't leak any data.  */
      explicit_bzero (__tls_internal.rand_state,
		      sizeof (*__tls_internal.rand_state));
      free (__tls_internal.rand_state);
    }
}
