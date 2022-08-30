/* Copyright (C) 1996-2022 Free Software Foundation, Inc.
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

/* Parts of this file are plain copies of the file `gethtnamadr.c' from
   the bind package and it has the following copyright.  */

/*
 * ++Copyright++ 1985, 1988, 1993
 * -
 * Copyright (c) 1985, 1988, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

#include <alloc_buffer.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <libc-pointer-arith.h>

#include "nsswitch.h"
#include <arpa/nameser.h>
#include <nss_dns.h>

#include <resolv/resolv-internal.h>
#include <resolv/resolv_context.h>

#define RESOLVSORT

#if PACKETSZ > 65536
# define MAXPACKET	PACKETSZ
#else
# define MAXPACKET	65536
#endif
/* As per RFC 1034 and 1035 a host name cannot exceed 255 octets in length.  */
#ifdef MAXHOSTNAMELEN
# undef MAXHOSTNAMELEN
#endif
#define MAXHOSTNAMELEN 256

/* We need this time later.  */
typedef union querybuf
{
  HEADER hdr;
  u_char buf[MAXPACKET];
} querybuf;

/* For historic reasons, pointers to IP addresses are char *, so use a
   single list type for addresses and host names.  */
#define DYNARRAY_STRUCT ptrlist
#define DYNARRAY_ELEMENT char *
#define DYNARRAY_PREFIX ptrlist_
#include <malloc/dynarray-skeleton.c>

static enum nss_status getanswer_r (unsigned char *packet, size_t packetlen,
				    uint16_t qtype, struct alloc_buffer *abuf,
				    struct ptrlist *addresses,
				    struct ptrlist *aliases,
				    int *errnop, int *h_errnop, int32_t *ttlp);
static void addrsort (struct resolv_context *ctx, char **ap, int num);
static enum nss_status getanswer_ptr (unsigned char *packet, size_t packetlen,
				      struct alloc_buffer *abuf,
				      char **hnamep, int *errnop,
				      int *h_errnop, int32_t *ttlp);

static enum nss_status gaih_getanswer (const querybuf *answer1, int anslen1,
				       const querybuf *answer2, int anslen2,
				       const char *qname,
				       struct gaih_addrtuple **pat,
				       char *buffer, size_t buflen,
				       int *errnop, int *h_errnop,
				       int32_t *ttlp);
static enum nss_status gaih_getanswer_noaaaa (const querybuf *answer1,
					      int anslen1,
					      const char *qname,
					      struct gaih_addrtuple **pat,
					      char *buffer, size_t buflen,
					      int *errnop, int *h_errnop,
					      int32_t *ttlp);


static enum nss_status gethostbyname3_context (struct resolv_context *ctx,
					       const char *name, int af,
					       struct hostent *result,
					       char *buffer, size_t buflen,
					       int *errnop, int *h_errnop,
					       int32_t *ttlp,
					       char **canonp);

/* Return the expected RDATA length for an address record type (A or
   AAAA).  */
static int
rrtype_to_rdata_length (int type)
{
  switch (type)
    {
    case T_A:
      return INADDRSZ;
    case T_AAAA:
      return IN6ADDRSZ;
    default:
      return -1;
    }
}


enum nss_status
_nss_dns_gethostbyname3_r (const char *name, int af, struct hostent *result,
			   char *buffer, size_t buflen, int *errnop,
			   int *h_errnop, int32_t *ttlp, char **canonp)
{
  struct resolv_context *ctx = __resolv_context_get ();
  if (ctx == NULL)
    {
      *errnop = errno;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }
  enum nss_status status = gethostbyname3_context
    (ctx, name, af, result, buffer, buflen, errnop, h_errnop, ttlp, canonp);
  __resolv_context_put (ctx);
  return status;
}
libc_hidden_def (_nss_dns_gethostbyname3_r)

static enum nss_status
gethostbyname3_context (struct resolv_context *ctx,
			const char *name, int af, struct hostent *result,
			char *buffer, size_t buflen, int *errnop,
			int *h_errnop, int32_t *ttlp, char **canonp)
{
  char tmp[NS_MAXDNAME];
  int size, type, n;
  const char *cp;
  int olderr = errno;
  enum nss_status status;

  switch (af) {
  case AF_INET:
    size = INADDRSZ;
    type = T_A;
    break;
  case AF_INET6:
    size = IN6ADDRSZ;
    type = T_AAAA;
    break;
  default:
    *h_errnop = NO_DATA;
    *errnop = EAFNOSUPPORT;
    return NSS_STATUS_UNAVAIL;
  }

  result->h_addrtype = af;
  result->h_length = size;

  /*
   * if there aren't any dots, it could be a user-level alias.
   * this is also done in res_query() since we are not the only
   * function that looks up host names.
   */
  if (strchr (name, '.') == NULL
      && (cp = __res_context_hostalias (ctx, name, tmp, sizeof (tmp))) != NULL)
    name = cp;

  unsigned char dns_packet_buffer[1024];
  unsigned char *alt_dns_packet_buffer = dns_packet_buffer;

  n = __res_context_search (ctx, name, C_IN, type,
			    dns_packet_buffer, sizeof (dns_packet_buffer),
			    &alt_dns_packet_buffer, NULL, NULL, NULL, NULL);
  if (n < 0)
    {
      switch (errno)
	{
	case ESRCH:
	  status = NSS_STATUS_TRYAGAIN;
	  h_errno = TRY_AGAIN;
	  break;
	/* System has run out of file descriptors.  */
	case EMFILE:
	case ENFILE:
	  h_errno = NETDB_INTERNAL;
	  /* Fall through.  */
	case ECONNREFUSED:
	case ETIMEDOUT:
	  status = NSS_STATUS_UNAVAIL;
	  break;
	default:
	  status = NSS_STATUS_NOTFOUND;
	  break;
	}
      *h_errnop = h_errno;
      if (h_errno == TRY_AGAIN)
	*errnop = EAGAIN;
      else
	__set_errno (olderr);
    }
  else
    {
      struct alloc_buffer abuf = alloc_buffer_create (buffer, buflen);

      struct ptrlist addresses;
      ptrlist_init (&addresses);
      struct ptrlist aliases;
      ptrlist_init (&aliases);

      status = getanswer_r (alt_dns_packet_buffer, n, type,
			    &abuf, &addresses, &aliases,
			    errnop, h_errnop, ttlp);
      if (status == NSS_STATUS_SUCCESS)
	{
	  if (ptrlist_has_failed (&addresses)
	      || ptrlist_has_failed (&aliases))
	    {
	      /* malloc failure.  Do not retry using the ERANGE protocol.  */
	      *errnop = ENOMEM;
	      *h_errnop = NETDB_INTERNAL;
	      status = NSS_STATUS_UNAVAIL;
	    }

	  /* Reserve the address and alias arrays in the result
	     buffer.  Both are NULL-terminated, but the first element
	     of the alias array is stored in h_name, so no extra space
	     for the NULL terminator is needed there.  */
	  result->h_addr_list
	    = alloc_buffer_alloc_array (&abuf, char *,
					ptrlist_size (&addresses) + 1);
	  result->h_aliases
	    = alloc_buffer_alloc_array (&abuf, char *,
					ptrlist_size (&aliases));
	  if (alloc_buffer_has_failed (&abuf))
	    {
	      /* Retry using the ERANGE protocol.  */
	      *errnop = ERANGE;
	      *h_errnop = NETDB_INTERNAL;
	      status = NSS_STATUS_TRYAGAIN;
	    }
	  else
	    {
	      /* Copy the address list and NULL-terminate it.  */
	      memcpy (result->h_addr_list, ptrlist_begin (&addresses),
		      ptrlist_size (&addresses) * sizeof (char *));
	      result->h_addr_list[ptrlist_size (&addresses)] = NULL;

	      /* Sort the address list if requested.  */
	      if (type == T_A && __resolv_context_sort_count (ctx) > 0)
		addrsort (ctx, result->h_addr_list, ptrlist_size (&addresses));

	      /* Copy the aliases,  excluding the last one. */
	      memcpy (result->h_aliases, ptrlist_begin (&aliases),
		      (ptrlist_size (&aliases) - 1) * sizeof (char *));
	      result->h_aliases[ptrlist_size (&aliases) - 1] = NULL;

	      /* The last alias goes into h_name.  */
	      assert (ptrlist_size (&aliases) >= 1);
	      result->h_name = ptrlist_end (&aliases)[-1];

	      /* This is also the canonical name.  */
	      if (canonp != NULL)
		*canonp = result->h_name;
	    }
	}

      ptrlist_free (&aliases);
      ptrlist_free (&addresses);
    }

  if (alt_dns_packet_buffer != dns_packet_buffer)
    free (alt_dns_packet_buffer);
  return status;
}

/* Verify that the name looks like a host name.  There is no point in
   sending a query which will not produce a usable name in the
   response.  */
static enum nss_status
check_name (const char *name, int *h_errnop)
{
  if (__libc_res_hnok (name))
    return NSS_STATUS_SUCCESS;
  *h_errnop = HOST_NOT_FOUND;
  return NSS_STATUS_NOTFOUND;
}

enum nss_status
_nss_dns_gethostbyname2_r (const char *name, int af, struct hostent *result,
			   char *buffer, size_t buflen, int *errnop,
			   int *h_errnop)
{
  enum nss_status status = check_name (name, h_errnop);
  if (status != NSS_STATUS_SUCCESS)
    return status;
  return _nss_dns_gethostbyname3_r (name, af, result, buffer, buflen, errnop,
				    h_errnop, NULL, NULL);
}
libc_hidden_def (_nss_dns_gethostbyname2_r)

enum nss_status
_nss_dns_gethostbyname_r (const char *name, struct hostent *result,
			  char *buffer, size_t buflen, int *errnop,
			  int *h_errnop)
{
  enum nss_status status = check_name (name, h_errnop);
  if (status != NSS_STATUS_SUCCESS)
    return status;
  struct resolv_context *ctx = __resolv_context_get ();
  if (ctx == NULL)
    {
      *errnop = errno;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }
  status = gethostbyname3_context (ctx, name, AF_INET, result, buffer,
				   buflen, errnop, h_errnop, NULL, NULL);
  __resolv_context_put (ctx);
  return status;
}
libc_hidden_def (_nss_dns_gethostbyname_r)

enum nss_status
_nss_dns_gethostbyname4_r (const char *name, struct gaih_addrtuple **pat,
			   char *buffer, size_t buflen, int *errnop,
			   int *herrnop, int32_t *ttlp)
{
  enum nss_status status = check_name (name, herrnop);
  if (status != NSS_STATUS_SUCCESS)
    return status;
  struct resolv_context *ctx = __resolv_context_get ();
  if (ctx == NULL)
    {
      *errnop = errno;
      *herrnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }

  /*
   * if there aren't any dots, it could be a user-level alias.
   * this is also done in res_query() since we are not the only
   * function that looks up host names.
   */
  if (strchr (name, '.') == NULL)
    {
      char *tmp = alloca (NS_MAXDNAME);
      const char *cp = __res_context_hostalias (ctx, name, tmp, NS_MAXDNAME);
      if (cp != NULL)
	name = cp;
    }

  union
  {
    querybuf *buf;
    u_char *ptr;
  } host_buffer;
  querybuf *orig_host_buffer;
  host_buffer.buf = orig_host_buffer = (querybuf *) alloca (2048);
  u_char *ans2p = NULL;
  int nans2p = 0;
  int resplen2 = 0;
  int ans2p_malloced = 0;


  int olderr = errno;
  int n;

  if ((ctx->resp->options & RES_NOAAAA) == 0)
    {
      n = __res_context_search (ctx, name, C_IN, T_QUERY_A_AND_AAAA,
				host_buffer.buf->buf, 2048, &host_buffer.ptr,
				&ans2p, &nans2p, &resplen2, &ans2p_malloced);
      if (n >= 0)
	status = gaih_getanswer (host_buffer.buf, n, (const querybuf *) ans2p,
				 resplen2, name, pat, buffer, buflen,
				 errnop, herrnop, ttlp);
    }
  else
    {
      n = __res_context_search (ctx, name, C_IN, T_A,
				host_buffer.buf->buf, 2048, NULL,
				NULL, NULL, NULL, NULL);
      if (n >= 0)
	status = gaih_getanswer_noaaaa (host_buffer.buf, n,
					name, pat, buffer, buflen,
					errnop, herrnop, ttlp);
    }
  if (n < 0)
    {
      switch (errno)
	{
	case ESRCH:
	  status = NSS_STATUS_TRYAGAIN;
	  h_errno = TRY_AGAIN;
	  break;
	/* System has run out of file descriptors.  */
	case EMFILE:
	case ENFILE:
	  h_errno = NETDB_INTERNAL;
	  /* Fall through.  */
	case ECONNREFUSED:
	case ETIMEDOUT:
	  status = NSS_STATUS_UNAVAIL;
	  break;
	default:
	  status = NSS_STATUS_NOTFOUND;
	  break;
	}

      *herrnop = h_errno;
      if (h_errno == TRY_AGAIN)
	*errnop = EAGAIN;
      else
	__set_errno (olderr);
    }

  /* Check whether ans2p was separately allocated.  */
  if (ans2p_malloced)
    free (ans2p);

  if (host_buffer.buf != orig_host_buffer)
    free (host_buffer.buf);

  __resolv_context_put (ctx);
  return status;
}
libc_hidden_def (_nss_dns_gethostbyname4_r)

enum nss_status
_nss_dns_gethostbyaddr2_r (const void *addr, socklen_t len, int af,
			   struct hostent *result, char *buffer, size_t buflen,
			   int *errnop, int *h_errnop, int32_t *ttlp)
{
  static const u_char mapped[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0xff,0xff };
  static const u_char tunnelled[] = { 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 };
  static const u_char v6local[] = { 0,0, 0,1 };
  const u_char *uaddr = (const u_char *)addr;
  char qbuf[MAXDNAME+1], *qp = NULL;
  size_t size;
  int n, status;
  int olderr = errno;

  /* Prepare the allocation buffer.  Store the pointer array first, to
     benefit from buffer alignment.  */
  struct alloc_buffer abuf = alloc_buffer_create (buffer, buflen);
  char **address_array = alloc_buffer_alloc_array (&abuf, char *, 2);
  if (address_array == NULL)
    {
      *errnop = ERANGE;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_TRYAGAIN;
    }

  struct resolv_context *ctx = __resolv_context_get ();
  if (ctx == NULL)
    {
      *errnop = errno;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_UNAVAIL;
    }

  if (af == AF_INET6 && len == IN6ADDRSZ
      && (memcmp (uaddr, mapped, sizeof mapped) == 0
	  || (memcmp (uaddr, tunnelled, sizeof tunnelled) == 0
	      && memcmp (&uaddr[sizeof tunnelled], v6local, sizeof v6local))))
    {
      /* Unmap. */
      addr += sizeof mapped;
      uaddr += sizeof mapped;
      af = AF_INET;
      len = INADDRSZ;
    }

  switch (af)
    {
    case AF_INET:
      size = INADDRSZ;
      break;
    case AF_INET6:
      size = IN6ADDRSZ;
      break;
    default:
      *errnop = EAFNOSUPPORT;
      *h_errnop = NETDB_INTERNAL;
      __resolv_context_put (ctx);
      return NSS_STATUS_UNAVAIL;
    }
  if (size > len)
    {
      *errnop = EAFNOSUPPORT;
      *h_errnop = NETDB_INTERNAL;
      __resolv_context_put (ctx);
      return NSS_STATUS_UNAVAIL;
    }

  switch (af)
    {
    case AF_INET:
      sprintf (qbuf, "%u.%u.%u.%u.in-addr.arpa", (uaddr[3] & 0xff),
	       (uaddr[2] & 0xff), (uaddr[1] & 0xff), (uaddr[0] & 0xff));
      break;
    case AF_INET6:
      qp = qbuf;
      for (n = IN6ADDRSZ - 1; n >= 0; n--)
	{
	  static const char nibblechar[16] = "0123456789abcdef";
	  *qp++ = nibblechar[uaddr[n] & 0xf];
	  *qp++ = '.';
	  *qp++ = nibblechar[(uaddr[n] >> 4) & 0xf];
	  *qp++ = '.';
	}
      strcpy(qp, "ip6.arpa");
      break;
    default:
      /* Cannot happen.  */
      break;
    }

  unsigned char dns_packet_buffer[1024];
  unsigned char *alt_dns_packet_buffer = dns_packet_buffer;
  n = __res_context_query (ctx, qbuf, C_IN, T_PTR,
			   dns_packet_buffer, sizeof (dns_packet_buffer),
			   &alt_dns_packet_buffer,
			   NULL, NULL, NULL, NULL);
  if (n < 0)
    {
      *h_errnop = h_errno;
      __set_errno (olderr);
      if (alt_dns_packet_buffer != dns_packet_buffer)
	free (alt_dns_packet_buffer);
      __resolv_context_put (ctx);
      return errno == ECONNREFUSED ? NSS_STATUS_UNAVAIL : NSS_STATUS_NOTFOUND;
    }

  status = getanswer_ptr (alt_dns_packet_buffer, n,
			  &abuf, &result->h_name, errnop, h_errnop, ttlp);

  if (alt_dns_packet_buffer != dns_packet_buffer)
    free (alt_dns_packet_buffer);
  __resolv_context_put (ctx);

  if (status != NSS_STATUS_SUCCESS)
    return status;

  /* result->h_name has already been set by getanswer_ptr.  */
  result->h_addrtype = af;
  result->h_length = len;
  /* Increase the alignment to 4, in case there are applications out
     there that expect at least this level of address alignment.  */
  address_array[0] = (char *) alloc_buffer_next (&abuf, uint32_t);
  alloc_buffer_copy_bytes (&abuf, uaddr, len);
  address_array[1] = NULL;

  /* This check also covers allocation failure in getanswer_ptr.  */
  if (alloc_buffer_has_failed (&abuf))
    {
      *errnop = ERANGE;
      *h_errnop = NETDB_INTERNAL;
      return NSS_STATUS_TRYAGAIN;
    }
  result->h_addr_list = address_array;
  result->h_aliases = &address_array[1]; /* Points to NULL.  */

  *h_errnop = NETDB_SUCCESS;
  return NSS_STATUS_SUCCESS;
}
libc_hidden_def (_nss_dns_gethostbyaddr2_r)


enum nss_status
_nss_dns_gethostbyaddr_r (const void *addr, socklen_t len, int af,
			  struct hostent *result, char *buffer, size_t buflen,
			  int *errnop, int *h_errnop)
{
  return _nss_dns_gethostbyaddr2_r (addr, len, af, result, buffer, buflen,
				    errnop, h_errnop, NULL);
}
libc_hidden_def (_nss_dns_gethostbyaddr_r)

static void
addrsort (struct resolv_context *ctx, char **ap, int num)
{
  int i, j;
  char **p;
  short aval[MAX_NR_ADDRS];
  int needsort = 0;
  size_t nsort = __resolv_context_sort_count (ctx);

  p = ap;
  if (num > MAX_NR_ADDRS)
    num = MAX_NR_ADDRS;
  for (i = 0; i < num; i++, p++)
    {
      for (j = 0 ; (unsigned)j < nsort; j++)
	{
	  struct resolv_sortlist_entry e
	    = __resolv_context_sort_entry (ctx, j);
	  if (e.addr.s_addr == (((struct in_addr *)(*p))->s_addr & e.mask))
	    break;
	}
      aval[i] = j;
      if (needsort == 0 && i > 0 && j < aval[i-1])
	needsort = i;
    }
  if (!needsort)
    return;

  while (needsort++ < num)
    for (j = needsort - 2; j >= 0; j--)
      if (aval[j] > aval[j+1])
	{
	  char *hp;

	  i = aval[j];
	  aval[j] = aval[j+1];
	  aval[j+1] = i;

	  hp = ap[j];
	  ap[j] = ap[j+1];
	  ap[j+1] = hp;
	}
      else
	break;
}

/* Convert the uncompressed, binary domain name CDNAME into its
   textual representation and add it to the end of ALIASES, allocating
   space for a copy of the name from ABUF.  Skip adding the name if it
   is not a valid host name, and return false in that case, otherwise
   true.  */
static bool
getanswer_r_store_alias (const unsigned char *cdname,
			 struct alloc_buffer *abuf,
			 struct ptrlist *aliases)
{
  /* Filter out domain names that are not host names.  */
  if (!__res_binary_hnok (cdname))
    return false;

  /* Note: Not NS_MAXCDNAME, so that __ns_name_ntop implicitly checks
     for length.  */
  char dname[MAXHOSTNAMELEN + 1];
  if (__ns_name_ntop (cdname, dname, sizeof (dname)) < 0)
    return false;
  /* Do not report an error on allocation failure, instead store NULL
     or do nothing.  getanswer_r's caller will see NSS_STATUS_SUCCESS
     and detect the memory allocation failure or buffer space
     exhaustion, and report it accordingly.  */
  ptrlist_add (aliases, alloc_buffer_copy_string (abuf, dname));
  return true;
}

static enum nss_status __attribute__ ((noinline))
getanswer_r (unsigned char *packet, size_t packetlen, uint16_t qtype,
	     struct alloc_buffer *abuf,
	     struct ptrlist *addresses, struct ptrlist *aliases,
	     int *errnop, int *h_errnop, int32_t *ttlp)
{
  struct ns_rr_cursor c;
  if (!__ns_rr_cursor_init (&c, packet, packetlen))
    {
      /* This should not happen because __res_context_query already
	 perfroms response validation.  */
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }

  /* Treat the QNAME just like an alias.  Error out if it is not a
     valid host name.  */
  if (ns_rr_cursor_rcode (&c) == NXDOMAIN
      || !getanswer_r_store_alias (ns_rr_cursor_qname (&c), abuf, aliases))
    {
      if (ttlp != NULL)
	/* No negative caching.  */
	*ttlp = 0;
      *h_errnop = HOST_NOT_FOUND;
      *errnop = ENOENT;
      return NSS_STATUS_NOTFOUND;
    }

  int ancount = ns_rr_cursor_ancount (&c);
  const unsigned char *expected_name = ns_rr_cursor_qname (&c);
  /* expected_name may be updated to point into this buffer.  */
  unsigned char name_buffer[NS_MAXCDNAME];

  for (; ancount > 0; --ancount)
    {
      struct ns_rr_wire rr;
      if (!__ns_rr_cursor_next (&c, &rr))
	{
	  *h_errnop = NO_RECOVERY;
	  return NSS_STATUS_UNAVAIL;
	}

      /* Skip over records with the wrong class.  */
      if (rr.rclass != C_IN)
	continue;

      /* Update TTL for recognized record types.  */
      if ((rr.rtype == T_CNAME || rr.rtype == qtype)
	  && ttlp != NULL && *ttlp > rr.ttl)
	*ttlp = rr.ttl;

      if (rr.rtype == T_CNAME)
	{
	  /* NB: No check for owner name match, based on historic
	     precedent.  Record the CNAME target as the new expected
	     name.  */
	  int n = __ns_name_unpack (c.begin, c.end, rr.rdata,
				    name_buffer, sizeof (name_buffer));
	  if (n < 0)
	    {
	      *h_errnop = NO_RECOVERY;
	      return NSS_STATUS_UNAVAIL;
	    }
	  /* And store the new name as an alias.  */
	  getanswer_r_store_alias (name_buffer, abuf, aliases);
	  expected_name = name_buffer;
	}
      else if (rr.rtype == qtype
	       && __ns_samebinaryname (rr.rname, expected_name)
	       && rr.rdlength == rrtype_to_rdata_length (qtype))
	{
	  /* Make a copy of the address and store it.  Increase the
	     alignment to 4, in case there are applications out there
	     that expect at least this level of address alignment.  */
	  ptrlist_add (addresses, (char *) alloc_buffer_next (abuf, uint32_t));
	  alloc_buffer_copy_bytes (abuf, rr.rdata, rr.rdlength);
	}
    }

  if (ptrlist_size (addresses) == 0)
    {
      /* No address record found.  */
      if (ttlp != NULL)
	/* No caching of negative responses.  */
	*ttlp = 0;

      *h_errnop = NO_RECOVERY;
      *errnop = ENOENT;
      return NSS_STATUS_TRYAGAIN;
    }
  else
    {
      *h_errnop = NETDB_SUCCESS;
      return NSS_STATUS_SUCCESS;
    }
}

static enum nss_status
getanswer_ptr (unsigned char *packet, size_t packetlen,
	       struct alloc_buffer *abuf, char **hnamep,
	       int *errnop, int *h_errnop, int32_t *ttlp)
{
  struct ns_rr_cursor c;
  if (!__ns_rr_cursor_init (&c, packet, packetlen))
    {
      /* This should not happen because __res_context_query already
	 perfroms response validation.  */
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  int ancount = ns_rr_cursor_ancount (&c);
  const unsigned char *expected_name = ns_rr_cursor_qname (&c);
  /* expected_name may be updated to point into this buffer.  */
  unsigned char name_buffer[NS_MAXCDNAME];

  while (ancount > 0)
    {
      struct ns_rr_wire rr;
      if (!__ns_rr_cursor_next (&c, &rr))
	{
	  *h_errnop = NO_RECOVERY;
	  return NSS_STATUS_UNAVAIL;
	}

      /* Skip over records with the wrong class.  */
      if (rr.rclass != C_IN)
	continue;

      /* Update TTL for known record types.  */
      if ((rr.rtype == T_CNAME || rr.rtype == T_PTR)
	  && ttlp != NULL && *ttlp > rr.ttl)
	*ttlp = rr.ttl;

      if (rr.rtype == T_CNAME)
	{
	  /* NB: No check for owner name match, based on historic
	     precedent.  Record the CNAME target as the new expected
	     name.  */
	  int n = __ns_name_unpack (c.begin, c.end, rr.rdata,
				    name_buffer, sizeof (name_buffer));
	  if (n < 0)
	    {
	      *h_errnop = NO_RECOVERY;
	      return NSS_STATUS_UNAVAIL;
	    }
	  expected_name = name_buffer;
	}
      else if (rr.rtype == T_PTR
	       && __ns_samebinaryname (rr.rname, expected_name))
	{
	  /* Decompress the target of the PTR record.  This is the
	     host name we are looking for.  We can only use it if it
	     is syntactically valid.  Historically, only one host name
	     is returned here.  If the recursive resolver performs DNS
	     record rotation, the returned host name is essentially
	     random, which is why multiple PTR records are rarely
	     used.  Use MAXHOSTNAMELEN instead of NS_MAXCDNAME for
	     additional length checking.  */
	  char hname[MAXHOSTNAMELEN + 1];
	  if (__ns_name_unpack (c.begin, c.end, rr.rdata,
				name_buffer, sizeof (name_buffer)) < 0
	      || !__res_binary_hnok (expected_name)
	      || __ns_name_ntop (name_buffer, hname, sizeof (hname)) < 0)
	    {
	      *h_errnop = NO_RECOVERY;
	      return NSS_STATUS_UNAVAIL;
	    }
	  /* Successful allocation is checked by the caller.  */
	  *hnamep = alloc_buffer_copy_string (abuf, hname);
	  return NSS_STATUS_SUCCESS;
	}
    }

  /* No PTR record found.  */
  if (ttlp != NULL)
    /* No caching of negative responses.  */
    *ttlp = 0;

  *h_errnop = NO_RECOVERY;
  *errnop = ENOENT;
  return NSS_STATUS_TRYAGAIN;
}

static enum nss_status
gaih_getanswer_slice (const querybuf *answer, int anslen, const char *qname,
		      struct gaih_addrtuple ***patp,
		      char **bufferp, size_t *buflenp,
		      int *errnop, int *h_errnop, int32_t *ttlp, int *firstp)
{
  char *buffer = *bufferp;
  size_t buflen = *buflenp;

  struct gaih_addrtuple **pat = *patp;
  const HEADER *hp = &answer->hdr;
  int ancount = ntohs (hp->ancount);
  int qdcount = ntohs (hp->qdcount);
  const u_char *cp = answer->buf + HFIXEDSZ;
  const u_char *end_of_message = answer->buf + anslen;
  if (__glibc_unlikely (qdcount != 1))
    {
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }

  u_char packtmp[NS_MAXCDNAME];
  int n = __ns_name_unpack (answer->buf, end_of_message, cp,
			    packtmp, sizeof packtmp);
  /* We unpack the name to check it for validity.  But we do not need
     it later.  */
  if (n != -1 && __ns_name_ntop (packtmp, buffer, buflen) == -1)
    {
      if (__glibc_unlikely (errno == EMSGSIZE))
	{
	too_small:
	  *errnop = ERANGE;
	  *h_errnop = NETDB_INTERNAL;
	  return NSS_STATUS_TRYAGAIN;
	}

      n = -1;
    }

  if (__glibc_unlikely (n < 0))
    {
      *errnop = errno;
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  if (__glibc_unlikely (__libc_res_hnok (buffer) == 0))
    {
      errno = EBADMSG;
      *errnop = EBADMSG;
      *h_errnop = NO_RECOVERY;
      return NSS_STATUS_UNAVAIL;
    }
  cp += n + QFIXEDSZ;

  int haveanswer = 0;
  int had_error = 0;
  char *canon = NULL;
  char *h_name = NULL;
  int h_namelen = 0;

  if (ancount == 0)
    {
      *h_errnop = HOST_NOT_FOUND;
      return NSS_STATUS_NOTFOUND;
    }

  while (ancount-- > 0 && cp < end_of_message && had_error == 0)
    {
      n = __ns_name_unpack (answer->buf, end_of_message, cp,
			    packtmp, sizeof packtmp);
      if (n != -1 &&
	  (h_namelen = __ns_name_ntop (packtmp, buffer, buflen)) == -1)
	{
	  if (__glibc_unlikely (errno == EMSGSIZE))
	    goto too_small;

	  n = -1;
	}
      if (__glibc_unlikely (n < 0 || __libc_res_hnok (buffer) == 0))
	{
	  ++had_error;
	  continue;
	}
      if (*firstp && canon == NULL)
	{
	  h_name = buffer;
	  buffer += h_namelen;
	  buflen -= h_namelen;
	}

      cp += n;				/* name */

      if (__glibc_unlikely (cp + 10 > end_of_message))
	{
	  ++had_error;
	  continue;
	}

      uint16_t type;
      NS_GET16 (type, cp);
      uint16_t class;
      NS_GET16 (class, cp);
      int32_t ttl;
      NS_GET32 (ttl, cp);
      NS_GET16 (n, cp);		/* RDATA length.  */

      if (end_of_message - cp < n)
	{
	  /* RDATA extends beyond the end of the packet.  */
	  ++had_error;
	  continue;
	}

      if (class != C_IN)
	{
	  cp += n;
	  continue;
	}

      if (type == T_CNAME)
	{
	  char tbuf[MAXDNAME];

	  /* A CNAME could also have a TTL entry.  */
	  if (ttlp != NULL && ttl < *ttlp)
	      *ttlp = ttl;

	  n = __libc_dn_expand (answer->buf, end_of_message, cp,
				tbuf, sizeof tbuf);
	  if (__glibc_unlikely (n < 0 || __libc_res_hnok (tbuf) == 0))
	    {
	      ++had_error;
	      continue;
	    }
	  cp += n;

	  if (*firstp)
	    {
	      /* Reclaim buffer space.  */
	      if (h_name + h_namelen == buffer)
		{
		  buffer = h_name;
		  buflen += h_namelen;
		}

	      n = strlen (tbuf) + 1;
	      if (__glibc_unlikely (n > buflen))
		goto too_small;
	      if (__glibc_unlikely (n >= MAXHOSTNAMELEN))
		{
		  ++had_error;
		  continue;
		}

	      canon = buffer;
	      buffer = __mempcpy (buffer, tbuf, n);
	      buflen -= n;
	      h_namelen = 0;
	    }
	  continue;
	}

      /* Stop parsing if we encounter a record with incorrect RDATA
	 length.  */
      if (type == T_A || type == T_AAAA)
	{
	  if (n != rrtype_to_rdata_length (type))
	    {
	      ++had_error;
	      continue;
	    }
	}
      else
	{
	  /* Skip unknown records.  */
	  cp += n;
	  continue;
	}

      assert (type == T_A || type == T_AAAA);
      if (*pat == NULL)
	{
	  uintptr_t pad = (-(uintptr_t) buffer
			   % __alignof__ (struct gaih_addrtuple));
	  buffer += pad;
	  buflen = buflen > pad ? buflen - pad : 0;

	  if (__glibc_unlikely (buflen < sizeof (struct gaih_addrtuple)))
	    goto too_small;

	  *pat = (struct gaih_addrtuple *) buffer;
	  buffer += sizeof (struct gaih_addrtuple);
	  buflen -= sizeof (struct gaih_addrtuple);
	}

      (*pat)->name = NULL;
      (*pat)->next = NULL;

      if (*firstp)
	{
	  /* We compose a single hostent out of the entire chain of
	     entries, so the TTL of the hostent is essentially the lowest
	     TTL in the chain.  */
	  if (ttlp != NULL && ttl < *ttlp)
	    *ttlp = ttl;

	  (*pat)->name = canon ?: h_name;

	  *firstp = 0;
	}

      (*pat)->family = type == T_A ? AF_INET : AF_INET6;
      memcpy ((*pat)->addr, cp, n);
      cp += n;
      (*pat)->scopeid = 0;

      pat = &((*pat)->next);

      haveanswer = 1;
    }

  if (haveanswer)
    {
      *patp = pat;
      *bufferp = buffer;
      *buflenp = buflen;

      *h_errnop = NETDB_SUCCESS;
      return NSS_STATUS_SUCCESS;
    }

  /* Special case here: if the resolver sent a result but it only
     contains a CNAME while we are looking for a T_A or T_AAAA record,
     we fail with NOTFOUND instead of TRYAGAIN.  */
  if (canon != NULL)
    {
      *h_errnop = HOST_NOT_FOUND;
      return NSS_STATUS_NOTFOUND;
    }

  *h_errnop = NETDB_INTERNAL;
  return NSS_STATUS_TRYAGAIN;
}


static enum nss_status
gaih_getanswer (const querybuf *answer1, int anslen1, const querybuf *answer2,
		int anslen2, const char *qname,
		struct gaih_addrtuple **pat, char *buffer, size_t buflen,
		int *errnop, int *h_errnop, int32_t *ttlp)
{
  int first = 1;

  enum nss_status status = NSS_STATUS_NOTFOUND;

  /* Combining the NSS status of two distinct queries requires some
     compromise and attention to symmetry (A or AAAA queries can be
     returned in any order).  What follows is a breakdown of how this
     code is expected to work and why. We discuss only SUCCESS,
     TRYAGAIN, NOTFOUND and UNAVAIL, since they are the only returns
     that apply (though RETURN and MERGE exist).  We make a distinction
     between TRYAGAIN (recoverable) and TRYAGAIN' (not-recoverable).
     A recoverable TRYAGAIN is almost always due to buffer size issues
     and returns ERANGE in errno and the caller is expected to retry
     with a larger buffer.

     Lastly, you may be tempted to make significant changes to the
     conditions in this code to bring about symmetry between responses.
     Please don't change anything without due consideration for
     expected application behaviour.  Some of the synthesized responses
     aren't very well thought out and sometimes appear to imply that
     IPv4 responses are always answer 1, and IPv6 responses are always
     answer 2, but that's not true (see the implementation of send_dg
     and send_vc to see response can arrive in any order, particularly
     for UDP). However, we expect it holds roughly enough of the time
     that this code works, but certainly needs to be fixed to make this
     a more robust implementation.

     ----------------------------------------------
     | Answer 1 Status /   | Synthesized | Reason |
     | Answer 2 Status     | Status      |        |
     |--------------------------------------------|
     | SUCCESS/SUCCESS     | SUCCESS     | [1]    |
     | SUCCESS/TRYAGAIN    | TRYAGAIN    | [5]    |
     | SUCCESS/TRYAGAIN'   | SUCCESS     | [1]    |
     | SUCCESS/NOTFOUND    | SUCCESS     | [1]    |
     | SUCCESS/UNAVAIL     | SUCCESS     | [1]    |
     | TRYAGAIN/SUCCESS    | TRYAGAIN    | [2]    |
     | TRYAGAIN/TRYAGAIN   | TRYAGAIN    | [2]    |
     | TRYAGAIN/TRYAGAIN'  | TRYAGAIN    | [2]    |
     | TRYAGAIN/NOTFOUND   | TRYAGAIN    | [2]    |
     | TRYAGAIN/UNAVAIL    | TRYAGAIN    | [2]    |
     | TRYAGAIN'/SUCCESS   | SUCCESS     | [3]    |
     | TRYAGAIN'/TRYAGAIN  | TRYAGAIN    | [3]    |
     | TRYAGAIN'/TRYAGAIN' | TRYAGAIN'   | [3]    |
     | TRYAGAIN'/NOTFOUND  | TRYAGAIN'   | [3]    |
     | TRYAGAIN'/UNAVAIL   | UNAVAIL     | [3]    |
     | NOTFOUND/SUCCESS    | SUCCESS     | [3]    |
     | NOTFOUND/TRYAGAIN   | TRYAGAIN    | [3]    |
     | NOTFOUND/TRYAGAIN'  | TRYAGAIN'   | [3]    |
     | NOTFOUND/NOTFOUND   | NOTFOUND    | [3]    |
     | NOTFOUND/UNAVAIL    | UNAVAIL     | [3]    |
     | UNAVAIL/SUCCESS     | UNAVAIL     | [4]    |
     | UNAVAIL/TRYAGAIN    | UNAVAIL     | [4]    |
     | UNAVAIL/TRYAGAIN'   | UNAVAIL     | [4]    |
     | UNAVAIL/NOTFOUND    | UNAVAIL     | [4]    |
     | UNAVAIL/UNAVAIL     | UNAVAIL     | [4]    |
     ----------------------------------------------

     [1] If the first response is a success we return success.
	 This ignores the state of the second answer and in fact
	 incorrectly sets errno and h_errno to that of the second
	 answer.  However because the response is a success we ignore
	 *errnop and *h_errnop (though that means you touched errno on
	 success).  We are being conservative here and returning the
	 likely IPv4 response in the first answer as a success.

     [2] If the first response is a recoverable TRYAGAIN we return
	 that instead of looking at the second response.  The
	 expectation here is that we have failed to get an IPv4 response
	 and should retry both queries.

     [3] If the first response was not a SUCCESS and the second
	 response is not NOTFOUND (had a SUCCESS, need to TRYAGAIN,
	 or failed entirely e.g. TRYAGAIN' and UNAVAIL) then use the
	 result from the second response, otherwise the first responses
	 status is used.  Again we have some odd side-effects when the
	 second response is NOTFOUND because we overwrite *errnop and
	 *h_errnop that means that a first answer of NOTFOUND might see
	 its *errnop and *h_errnop values altered.  Whether it matters
	 in practice that a first response NOTFOUND has the wrong
	 *errnop and *h_errnop is undecided.

     [4] If the first response is UNAVAIL we return that instead of
	 looking at the second response.  The expectation here is that
	 it will have failed similarly e.g. configuration failure.

     [5] Testing this code is complicated by the fact that truncated
	 second response buffers might be returned as SUCCESS if the
	 first answer is a SUCCESS.  To fix this we add symmetry to
	 TRYAGAIN with the second response.  If the second response
	 is a recoverable error we now return TRYAGIN even if the first
	 response was SUCCESS.  */

  if (anslen1 > 0)
    status = gaih_getanswer_slice(answer1, anslen1, qname,
				  &pat, &buffer, &buflen,
				  errnop, h_errnop, ttlp,
				  &first);

  if ((status == NSS_STATUS_SUCCESS || status == NSS_STATUS_NOTFOUND
       || (status == NSS_STATUS_TRYAGAIN
	   /* We want to look at the second answer in case of an
	      NSS_STATUS_TRYAGAIN only if the error is non-recoverable, i.e.
	      *h_errnop is NO_RECOVERY. If not, and if the failure was due to
	      an insufficient buffer (ERANGE), then we need to drop the results
	      and pass on the NSS_STATUS_TRYAGAIN to the caller so that it can
	      repeat the query with a larger buffer.  */
	   && (*errnop != ERANGE || *h_errnop == NO_RECOVERY)))
      && answer2 != NULL && anslen2 > 0)
    {
      enum nss_status status2 = gaih_getanswer_slice(answer2, anslen2, qname,
						     &pat, &buffer, &buflen,
						     errnop, h_errnop, ttlp,
						     &first);
      /* Use the second response status in some cases.  */
      if (status != NSS_STATUS_SUCCESS && status2 != NSS_STATUS_NOTFOUND)
	status = status2;
      /* Do not return a truncated second response (unless it was
	 unavoidable e.g. unrecoverable TRYAGAIN).  */
      if (status == NSS_STATUS_SUCCESS
	  && (status2 == NSS_STATUS_TRYAGAIN
	      && *errnop == ERANGE && *h_errnop != NO_RECOVERY))
	status = NSS_STATUS_TRYAGAIN;
    }

  return status;
}

/* Variant of gaih_getanswer without a second (AAAA) response.  */
static enum nss_status
gaih_getanswer_noaaaa (const querybuf *answer1, int anslen1, const char *qname,
		       struct gaih_addrtuple **pat,
		       char *buffer, size_t buflen,
		       int *errnop, int *h_errnop, int32_t *ttlp)
{
  int first = 1;

  enum nss_status status = NSS_STATUS_NOTFOUND;
  if (anslen1 > 0)
    status = gaih_getanswer_slice (answer1, anslen1, qname,
				   &pat, &buffer, &buflen,
				   errnop, h_errnop, ttlp,
				   &first);
  return status;
}
