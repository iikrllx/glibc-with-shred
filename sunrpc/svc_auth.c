/*
 * svc_auth.c, Server-side rpc authenticator interface.
 *
 * Copyright (c) 2010, Oracle America, Inc.
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
 *     * Neither the name of the "Oracle America, Inc." nor the names of its
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
#include <rpc/svc_auth.h>

/*
 * svcauthsw is the bdevsw of server side authentication.
 *
 * Server side authenticators are called from authenticate by
 * using the client auth struct flavor field to index into svcauthsw.
 * The server auth flavors must implement a routine that looks
 * like:
 *
 *      enum auth_stat
 *      flavorx_auth(rqst, msg)
 *              register struct svc_req *rqst;
 *              register struct rpc_msg *msg;
 *
 */

static enum auth_stat _svcauth_null (struct svc_req *, struct rpc_msg *);
				/* no authentication */
extern enum auth_stat _svcauth_unix (struct svc_req *, struct rpc_msg *);
				/* unix style (uid, gids) */
extern enum auth_stat _svcauth_short (struct svc_req *, struct rpc_msg *);
				/* short hand unix style */
extern enum auth_stat _svcauth_des (struct svc_req *, struct rpc_msg *);
				/* des style */

static const struct
  {
    enum auth_stat (*authenticator) (struct svc_req *, struct rpc_msg *);
  }
svcauthsw[] =
{
  { _svcauth_null },		/* AUTH_NULL */
  { _svcauth_unix },		/* AUTH_UNIX */
  { _svcauth_short },		/* AUTH_SHORT */
  { _svcauth_des }		/* AUTH_DES */
};
#define	AUTH_MAX	3	/* HIGHEST AUTH NUMBER */


/*
 * The call rpc message, msg has been obtained from the wire.  The msg contains
 * the raw form of credentials and verifiers.  authenticate returns AUTH_OK
 * if the msg is successfully authenticated.  If AUTH_OK then the routine also
 * does the following things:
 * set rqst->rq_xprt->verf to the appropriate response verifier;
 * sets rqst->rq_client_cred to the "cooked" form of the credentials.
 *
 * NB: rqst->rq_cxprt->verf must be pre-allocated;
 * its length is set appropriately.
 *
 * The caller still owns and is responsible for msg->u.cmb.cred and
 * msg->u.cmb.verf.  The authentication system retains ownership of
 * rqst->rq_client_cred, the cooked credentials.
 *
 * There is an assumption that any flavour less than AUTH_NULL is
 * invalid.
 */
enum auth_stat
_authenticate (register struct svc_req *rqst, struct rpc_msg *msg)
{
  register int cred_flavor;

  rqst->rq_cred = msg->rm_call.cb_cred;
  rqst->rq_xprt->xp_verf.oa_flavor = _null_auth.oa_flavor;
  rqst->rq_xprt->xp_verf.oa_length = 0;
  cred_flavor = rqst->rq_cred.oa_flavor;
  if ((cred_flavor <= AUTH_MAX) && (cred_flavor >= AUTH_NULL))
    return (*(svcauthsw[cred_flavor].authenticator)) (rqst, msg);

  return AUTH_REJECTEDCRED;
}
INTDEF(_authenticate)

static enum auth_stat
_svcauth_null (struct svc_req *rqst, struct rpc_msg *msg)
{
  return AUTH_OK;
}
