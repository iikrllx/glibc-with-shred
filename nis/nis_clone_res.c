/* Copyright (c) 1997, 1998, 2005 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1997.

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

#include <string.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

#include "nis_xdr.h"

nis_result *
nis_clone_result (const nis_result *src, nis_result *dest)
{
  char *addr;
  unsigned int size;
  XDR xdrs;
  nis_result *res;

  if (src == NULL)
    return (NULL);

  size = xdr_sizeof ((xdrproc_t)_xdr_nis_result, (char *)src);
  if ((addr = calloc(1, size)) == NULL)
    return NULL;

  if (dest == NULL)
    {
      if ((res = calloc (1, sizeof (nis_result))) == NULL)
	{
	  free (addr);
	  return NULL;
	}
    }
  else
    res = dest;

  xdrmem_create(&xdrs, addr, size, XDR_ENCODE);
  if (!_xdr_nis_result (&xdrs, (nis_result *)src))
    {
      xdr_destroy (&xdrs);
      free (addr);
      return NULL;
    }
  xdr_destroy (&xdrs);
  xdrmem_create(&xdrs, addr, size, XDR_DECODE);
  if (!_xdr_nis_result(&xdrs, res))
    {
      xdr_destroy (&xdrs);
      free (addr);
      return NULL;
    }
  xdr_destroy (&xdrs);
  free (addr);

  return res;
}
