/* Copyright (C) 1997, 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1997.

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

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/nis.h>

#include "nis_intern.h"

/* Private data kept per client handle, from sunrpc/clnt_udp.c */
struct cu_data
  {
    int cu_sock;
    bool_t cu_closeit;
    struct sockaddr_in cu_raddr;
    int cu_rlen;
    struct timeval cu_wait;
    struct timeval cu_total;
    struct rpc_err cu_error;
    XDR cu_outxdrs;
    u_int cu_xdrpos;
    u_int cu_sendsz;
    char *cu_outbuf;
    u_int cu_recvsz;
    char cu_inbuf[1];
  };


/* The following is the original routine from sunrpc/pm_getport.c.
   The only change is the much shorter timeout. */
/*
 * pmap_getport.c
 * Client interface to pmap rpc service.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

/*
 * Find the mapped port for program,version.
 * Calls the pmap service remotely to do the lookup.
 * Returns 0 if no map exists.
 */
u_short
__pmap_getnisport (struct sockaddr_in *address, u_long program,
		   u_long version, u_int protocol)
{
  const struct timeval timeout = {1, 0};
  const struct timeval tottimeout = {1, 0};
  u_short port = 0;
  int socket = -1;
  CLIENT *client;
  struct pmap parms;

  address->sin_port = htons (PMAPPORT);
  client = clntudp_bufcreate (address, PMAPPROG, PMAPVERS, timeout, &socket,
			      RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
  if (client != (CLIENT *) NULL)
    {
      parms.pm_prog = program;
      parms.pm_vers = version;
      parms.pm_prot = protocol;
      parms.pm_port = 0;	/* not needed or used */
      if (CLNT_CALL (client, PMAPPROC_GETPORT, (xdrproc_t) xdr_pmap,
		     (caddr_t) & parms, (xdrproc_t) xdr_u_short,
		     (caddr_t) & port, tottimeout) != RPC_SUCCESS)
	{
	  rpc_createerr.cf_stat = RPC_PMAPFAILURE;
	  clnt_geterr (client, &rpc_createerr.cf_error);
	}
      else
	{
	  if (port == 0)
	    rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
	}
      CLNT_DESTROY (client);
    }
  /* (void)close(socket); CLNT_DESTROY already closed it */
  address->sin_port = 0;
  return port;
}

/* This is now the public function, which should find the fastest server */

struct findserv_req
{
  struct sockaddr_in sin;
  u_int32_t xid;
  u_int server_nr;
  u_int server_ep;
};

long
__nis_findfastest (dir_binding * bind)
{
  const struct timeval TIMEOUT50 = {5, 0};
  const struct timeval TIMEOUT00 = {0, 0};
  struct findserv_req **pings;
  struct sockaddr_in sin, saved_sin;
  int found = -1;
  u_int32_t xid_seed, xid_lookup;
  int sock, dontblock = 1;
  CLIENT *clnt;
  char clnt_res;
  void *foo = NULL;
  u_long i, j, pings_count, pings_max;
  struct cu_data *cu;

  pings_max = bind->server_len * 2;	/* Reserve a little bit more memory
					   for multihomed hosts */
  pings_count = 0;
  pings = malloc (sizeof (struct findserv_req *) * pings_max);
  xid_seed = (u_int32_t) (time (NULL) ^ getpid ());

  memset (&sin, '\0', sizeof (sin));
  sin.sin_family = AF_INET;
  for (i = 0; i < bind->server_len; i++)
    for (j = 0; j < bind->server_val[i].ep.ep_len; ++j)
      if (strcmp (bind->server_val[i].ep.ep_val[j].family, "inet") == 0)
	if ((bind->server_val[i].ep.ep_val[j].proto == NULL) ||
	    (strcmp (bind->server_val[i].ep.ep_val[j].proto, "-") == 0) ||
	    (strlen (bind->server_val[i].ep.ep_val[j].proto) == 0))
	  {
	    sin.sin_addr.s_addr =
	      inetstr2int (bind->server_val[i].ep.ep_val[j].uaddr);
	    if (sin.sin_addr.s_addr == 0)
	      continue;
	    sin.sin_port = htons (__pmap_getnisport (&sin, NIS_PROG,
						     NIS_VERSION,
						     IPPROTO_UDP));
	    if (sin.sin_port == 0)
	      continue;

	    if (pings_count >= pings_max)
	      {
		pings_max += 10;
		pings = realloc (pings, sizeof (struct findserv_req) *
				 pings_max);
	      }
	    pings[pings_count] = calloc (1, sizeof (struct findserv_req));
	    memcpy ((char *) &pings[pings_count]->sin, (char *) &sin,
		    sizeof (sin));
	    memcpy ((char *)&saved_sin, (char *)&sin, sizeof(sin));
	    pings[pings_count]->xid = xid_seed;
	    pings[pings_count]->server_nr = i;
	    pings[pings_count]->server_ep = j;
	    ++xid_seed;
	    ++pings_count;
	  }

  /* Make sure at least one server was assigned */
  if (pings_count == 0)
    {
      free (pings);
      return -1;
    }

  /* Create RPC handle */
  sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  clnt = clntudp_create (&saved_sin, NIS_PROG, NIS_VERSION, TIMEOUT50, &sock);
  if (clnt == NULL)
    {
      close (sock);
      for (i = 0; i < pings_count; ++i)
	free (pings[i]);
      free (pings);
      return -1;
    }
  auth_destroy (clnt->cl_auth);
  clnt->cl_auth = authunix_create_default ();
  cu = (struct cu_data *) clnt->cl_private;
  clnt_control (clnt, CLSET_TIMEOUT, (char *) &TIMEOUT00);
  ioctl (sock, FIONBIO, &dontblock);

  /* Send to all servers the NULLPROC */
  for (i = 0; i < pings_count; ++i)
    {
      /* clntudp_call() will increment, subtract one */
      *((u_int32_t *) (cu->cu_outbuf)) = pings[i]->xid - 1;
      memcpy ((char *) &cu->cu_raddr, (char *) &pings[i]->sin,
	      sizeof (struct sockaddr_in));
      /* Transmit to NULLPROC, return immediately. */
      clnt_call (clnt, NULLPROC, (xdrproc_t) xdr_void, (caddr_t) foo,
		 (xdrproc_t) xdr_void, (caddr_t) & clnt_res, TIMEOUT00);
    }

  /* Receive reply from NULLPROC asynchronously */
  memset ((char *) &clnt_res, 0, sizeof (clnt_res));
  clnt_call (clnt, NULLPROC, (xdrproc_t) NULL, (caddr_t) foo,
	     (xdrproc_t) xdr_void, (caddr_t) &clnt_res, TIMEOUT00);

  xid_lookup = *((u_int32_t *) (cu->cu_inbuf));
  for (i = 0; i < pings_count; i++)
    {
      if (pings[i]->xid == xid_lookup)
	{
	  bind->server_used = pings[i]->server_nr;
	  bind->current_ep = pings[i]->server_ep;
	  found = 1;
	}
    }

  auth_destroy (clnt->cl_auth);
  clnt_destroy (clnt);
  close (sock);

  for (i = 0; i < pings_count; ++i)
    free (pings[i]);
  free (pings);

  return found;
}
