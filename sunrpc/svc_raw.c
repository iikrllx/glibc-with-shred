/*
 * svc_raw.c,   This a toy for simple testing and timing.
 * Interface to create an rpc client and server in the same UNIX process.
 * This lets us simulate rpc and get rpc (round trip) overhead, without
 * any interference from the kernel.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of Sun Microsystems, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *   COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rpc/rpc.h>
#include <rpc/svc.h>

/*
 * This is the "network" that we will be moving data over
 */
struct svcraw_private_s
  {
    char _raw_buf[UDPMSGSIZE];
    SVCXPRT server;
    XDR xdr_stream;
    char verf_body[MAX_AUTH_BYTES];
  };
#ifdef _RPC_THREAD_SAFE_
#define svcraw_private RPC_THREAD_VARIABLE(svcraw_private_s)
#else
static struct svcraw_private_s *svcraw_private;
#endif

static bool_t svcraw_recv (SVCXPRT *, struct rpc_msg *);
static enum xprt_stat svcraw_stat (SVCXPRT *);
static bool_t svcraw_getargs (SVCXPRT *, xdrproc_t, caddr_t);
static bool_t svcraw_reply (SVCXPRT *, struct rpc_msg *);
static bool_t svcraw_freeargs (SVCXPRT *, xdrproc_t, caddr_t);
static void svcraw_destroy (SVCXPRT *);

static const struct xp_ops server_ops =
{
  svcraw_recv,
  svcraw_stat,
  svcraw_getargs,
  svcraw_reply,
  svcraw_freeargs,
  svcraw_destroy
};

SVCXPRT *
svcraw_create (void)
{
  struct svcraw_private_s *srp = svcraw_private;

  if (srp == 0)
    {
      srp = (struct svcraw_private_s *) calloc (1, sizeof (*srp));
      if (srp == 0)
	return NULL;
    }
  srp->server.xp_sock = 0;
  srp->server.xp_port = 0;
  srp->server.xp_ops = (struct xp_ops *) &server_ops;
  srp->server.xp_verf.oa_base = srp->verf_body;
  INTUSE(xdrmem_create) (&srp->xdr_stream, srp->_raw_buf, UDPMSGSIZE,
			 XDR_FREE);
  return &srp->server;
}

static enum xprt_stat
svcraw_stat (SVCXPRT *xprt)
{
  return XPRT_IDLE;
}

static bool_t
svcraw_recv (xprt, msg)
     SVCXPRT *xprt;
     struct rpc_msg *msg;
{
  struct svcraw_private_s *srp = svcraw_private;
  XDR *xdrs;

  if (srp == 0)
    return FALSE;
  xdrs = &srp->xdr_stream;
  xdrs->x_op = XDR_DECODE;
  XDR_SETPOS (xdrs, 0);
  if (!INTUSE(xdr_callmsg) (xdrs, msg))
    return FALSE;
  return TRUE;
}

static bool_t
svcraw_reply (SVCXPRT *xprt, struct rpc_msg *msg)
{
  struct svcraw_private_s *srp = svcraw_private;
  XDR *xdrs;

  if (srp == 0)
    return FALSE;
  xdrs = &srp->xdr_stream;
  xdrs->x_op = XDR_ENCODE;
  XDR_SETPOS (xdrs, 0);
  if (!INTUSE(xdr_replymsg) (xdrs, msg))
    return FALSE;
  (void) XDR_GETPOS (xdrs);	/* called just for overhead */
  return TRUE;
}

static bool_t
svcraw_getargs (SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
  struct svcraw_private_s *srp = svcraw_private;

  if (srp == 0)
    return FALSE;
  return (*xdr_args) (&srp->xdr_stream, args_ptr);
}

static bool_t
svcraw_freeargs (SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
  struct svcraw_private_s *srp = svcraw_private;
  XDR *xdrs;

  if (srp == 0)
    return FALSE;
  xdrs = &srp->xdr_stream;
  xdrs->x_op = XDR_FREE;
  return (*xdr_args) (xdrs, args_ptr);
}

static void
svcraw_destroy (SVCXPRT *xprt)
{
}
