/* Copyright (C) 1996, 1997, 1998, 1999, 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Extended from original form by Ulrich Drepper <drepper@cygnus.com>, 1996.

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

/* Parts of this file are plain copies of the file `getnetnamadr.c' from
   the bind package and it has the following copyright.  */

/* Copyright (c) 1993 Carlos Leandro and Rui Salgueiro
 *      Dep. Matematica Universidade de Coimbra, Portugal, Europe
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */
/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
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
 */

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsswitch.h"
#include <arpa/inet.h>

/* Maximum number of aliases we allow.  */
#define MAX_NR_ALIASES	48


#if PACKETSZ > 65536
# define MAXPACKET	PACKETSZ
#else
# define MAXPACKET	65536
#endif


typedef enum
{
  BYADDR,
  BYNAME
} lookup_method;


/* We need this time later.  */
typedef union querybuf
{
  HEADER hdr;
  u_char buf[MAXPACKET];
} querybuf;

/* These functions are defined in res_comp.c.  */
#define NS_MAXCDNAME	255	/* maximum compressed domain name */
extern int __ns_name_ntop __P ((const u_char *, char *, size_t));
extern int __ns_name_unpack __P ((const u_char *, const u_char *,
				  const u_char *, u_char *, size_t));


/* Prototypes for local functions.  */
static enum nss_status getanswer_r (const querybuf *answer, int anslen,
				    struct netent *result, char *buffer,
				    size_t buflen, lookup_method net_i);


enum nss_status
_nss_dns_getnetbyname_r (const char *name, struct netent *result,
			 char *buffer, size_t buflen, int *errnop,
			 int *herrnop)
{
  /* Return entry for network with NAME.  */
  querybuf net_buffer;
  int anslen;
  char *qbuf;

  if ((_res.options & RES_INIT) == 0 && __res_ninit (&_res) == -1)
    return NSS_STATUS_UNAVAIL;

  qbuf = strdupa (name);
  anslen = res_nsearch (&_res, qbuf, C_IN, T_PTR, (u_char *) &net_buffer,
			sizeof (querybuf));
  if (anslen < 0)
    {
      /* Nothing found.  */
      *errnop = errno;
      return (errno == ECONNREFUSED
	      || errno == EPFNOSUPPORT
	      || errno == EAFNOSUPPORT)
	? NSS_STATUS_UNAVAIL : NSS_STATUS_NOTFOUND;
    }

  return getanswer_r (&net_buffer, anslen, result, buffer, buflen, BYNAME);
}


enum nss_status
_nss_dns_getnetbyaddr_r (uint32_t net, int type, struct netent *result,
			 char *buffer, size_t buflen, int *errnop,
			 int *herrnop)
{
  /* Return entry for network with NAME.  */
  enum nss_status status;
  querybuf net_buffer;
  unsigned int net_bytes[4];
  char qbuf[MAXDNAME];
  int cnt, anslen;
  u_int32_t net2;
  int olderr = errno;

  /* No net address lookup for IPv6 yet.  */
  if (type != AF_INET)
    return NSS_STATUS_UNAVAIL;

  if ((_res.options & RES_INIT) == 0 && __res_ninit (&_res) == -1)
    return NSS_STATUS_UNAVAIL;

  net2 = (u_int32_t) net;
  for (cnt = 4; net2 != 0; net2 >>= 8)
    net_bytes[--cnt] = net2 & 0xff;

  switch (cnt)
    {
    case 3:
      /* Class A network.  */
      sprintf (qbuf, "0.0.0.%u.in-addr.arpa", net_bytes[3]);
      break;
    case 2:
      /* Class B network.  */
      sprintf (qbuf, "0.0.%u.%u.in-addr.arpa", net_bytes[3], net_bytes[2]);
      break;
    case 1:
      /* Class C network.  */
      sprintf (qbuf, "0.%u.%u.%u.in-addr.arpa", net_bytes[3], net_bytes[2],
	       net_bytes[1]);
      break;
    case 0:
      /* Class D - E network.  */
      sprintf (qbuf, "%u.%u.%u.%u.in-addr.arpa", net_bytes[3], net_bytes[2],
	       net_bytes[1], net_bytes[0]);
      break;
    }

  anslen = res_nquery (&_res, qbuf, C_IN, T_PTR, (u_char *) &net_buffer,
		       sizeof (querybuf));
  if (anslen < 0)
    {
      /* Nothing found.  */
      int err = errno;
      __set_errno (olderr);
      return (err == ECONNREFUSED
	      || err == EPFNOSUPPORT
	      || err == EAFNOSUPPORT)
	? NSS_STATUS_UNAVAIL : NSS_STATUS_NOTFOUND;
    }

  status = getanswer_r (&net_buffer, anslen, result, buffer, buflen, BYADDR);
  if (status == NSS_STATUS_SUCCESS)
    {
      /* Strip trailing zeros.  */
      unsigned int u_net = net;	/* Maybe net should be unsigned?  */

      while ((u_net & 0xff) == 0 && u_net != 0)
	u_net >>= 8;
      result->n_net = u_net;
    }

  return status;
}


#undef offsetof
#define offsetof(Type, Member) ((size_t) &((Type *) NULL)->Member)

static enum nss_status
getanswer_r (const querybuf *answer, int anslen, struct netent *result,
	     char *buffer, size_t buflen, lookup_method net_i)
{
  /*
   * Find first satisfactory answer
   *
   *      answer --> +------------+  ( MESSAGE )
   *                 |   Header   |
   *                 +------------+
   *                 |  Question  | the question for the name server
   *                 +------------+
   *                 |   Answer   | RRs answering the question
   *                 +------------+
   *                 | Authority  | RRs pointing toward an authority
   *                 | Additional | RRs holding additional information
   *                 +------------+
   */
  struct net_data
  {
    char *aliases[MAX_NR_ALIASES];
    char linebuffer[0];
  } *net_data = (struct net_data *) buffer;
  int linebuflen = buflen - offsetof (struct net_data, linebuffer);
  const char *end_of_message = &answer->buf[anslen];
  const HEADER *header_pointer = &answer->hdr;
  /* #/records in the answer section.  */
  int answer_count =  ntohs (header_pointer->ancount);
  /* #/entries in the question section.  */
  int question_count = ntohs (header_pointer->qdcount);
  char *bp = net_data->linebuffer;
  const char *cp = &answer->buf[HFIXEDSZ];
  char **alias_pointer;
  int have_answer;
  char *ans;
  u_char packtmp[NS_MAXCDNAME];

  if (question_count == 0)
    {
      /* FIXME: the Sun version uses for host name lookup an additional
	 parameter for pointing to h_errno.  this is missing here.
	 OSF/1 has a per-thread h_errno variable.  */
      if (header_pointer->aa != 0)
	{
	  __set_h_errno (HOST_NOT_FOUND);
	  return NSS_STATUS_NOTFOUND;
	}
      else
	{
	  __set_h_errno (TRY_AGAIN);
	  return NSS_STATUS_TRYAGAIN;
	}
    }

  /* Skip the question part.  */
  while (question_count-- > 0)
    cp += __dn_skipname (cp, end_of_message) + QFIXEDSZ;

  alias_pointer = result->n_aliases = &net_data->aliases[0];
  *alias_pointer = NULL;
  have_answer = 0;
  ans = NULL;

  while (--answer_count >= 0 && cp < end_of_message)
    {
      int n = dn_expand (answer->buf, end_of_message, cp, bp, linebuflen);
      int type, class;

      n = __ns_name_unpack (answer->buf, end_of_message, cp,
			    packtmp, sizeof packtmp);
      if (n != -1 && __ns_name_ntop (packtmp, bp, linebuflen) == -1)
	{
	  if (errno == EMSGSIZE)
	    {
	      errno = ERANGE;
	      return NSS_STATUS_TRYAGAIN;
	    }

	  n = -1;
	}

      if (n > 0 && bp[0] == '.')
	bp[0] = '\0';

      if (n < 0 || res_dnok (bp) == 0)
	break;
      cp += n;
      ans = strdupa (bp);
      GETSHORT (type, cp);
      GETSHORT (class, cp);
      cp += INT32SZ;		/* TTL */
      GETSHORT (n, cp);

      if (class == C_IN && type == T_PTR)
	{
	  n = __ns_name_unpack (answer->buf, end_of_message, cp,
				packtmp, sizeof packtmp);
	  if (n != -1 && __ns_name_ntop (packtmp, bp, linebuflen) == -1)
	    {
	      if (errno == EMSGSIZE)
		{
		  errno = ERANGE;
		  return NSS_STATUS_TRYAGAIN;
		}

	      n = -1;
	    }

	  if (n < 0 || !res_hnok (bp))
	    {
	      /* XXX What does this mean?  The original form from bind
		 returns NULL. Incrementing cp has no effect in any case.
		 What should I return here. ??? */
	      cp += n;
	      return NSS_STATUS_UNAVAIL;
	    }
	  cp += n;
	  *alias_pointer++ = bp;
	  n = strlen (bp) + 1;
	  bp += n;
	  linebuflen -= n;
	  result->n_addrtype = class == C_IN ? AF_INET : AF_UNSPEC;
	  ++have_answer;
	}
    }

  if (have_answer)
    {
      char *tmp;
      int len;
      char *in, *cp, *rp, *wp;
      int cnt, first_flag;

      *alias_pointer = NULL;
      switch (net_i)
	{
	case BYADDR:
	  result->n_name = result->n_aliases[0];
	  result->n_net = 0L;
	  break;
	case BYNAME:
	  len = strlen (result->n_aliases[0]);
	  tmp = (char *) alloca (len + 1);
	  tmp[len] = 0;
	  wp = &tmp[len - 1];

	  rp = in = result->n_aliases[0];
	  result->n_name = ans;

	  first_flag = 1;
	  for (cnt = 0; cnt < 4; ++cnt)
	    {
	      char *startp;

	      startp = rp;
	      while (*rp != '.')
		++rp;
	      if (rp - startp > 1 || *startp != '0' || !first_flag)
		{
		  first_flag = 0;
		  if (cnt > 0)
		    *wp-- = '.';
		  cp = rp;
		  while (cp > startp)
		    *wp-- = *--cp;
		}
	      in = rp + 1;
	    }

	  result->n_net = inet_network (wp);
	  break;
	}

      ++result->n_aliases;
      return NSS_STATUS_SUCCESS;
    }

  __set_h_errno (TRY_AGAIN);
  return NSS_STATUS_TRYAGAIN;
}
