/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * The original source is from the RPCSRC 4.0 package from Sun Microsystems.
 * The Interface to keyserver protocoll 2 was added by
 * Thorsten Kukuk <kukuk@vt.uni-paderborn.de>
 */

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/auth.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <rpc/key_prot.h>

#define KEY_TIMEOUT	5	/* per-try timeout in seconds */
#define KEY_NRETRY	12	/* number of retries */

#define debug(msg)		/* turn off debugging */

extern int _openchild (char *command, FILE **fto, FILE **ffrom);


static int key_call (u_long, xdrproc_t xdr_arg, char *,
		     xdrproc_t xdr_rslt, char *);

static struct timeval trytimeout = {KEY_TIMEOUT, 0};
static struct timeval tottimeout = {KEY_TIMEOUT *KEY_NRETRY, 0};

int
key_setsecret (char *secretkey)
{
  keystatus status;

  if (!key_call ((u_long) KEY_SET, (xdrproc_t) xdr_keybuf, secretkey,
		 (xdrproc_t) xdr_keystatus, (char *) &status))
    return -1;
  if (status != KEY_SUCCESS)
    {
      debug ("set status is nonzero");
      return -1;
    }
  return 0;
}

/* key_secretkey_is_set() returns 1 if the keyserver has a secret key
 * stored for the caller's effective uid; it returns 0 otherwise
 *
 * N.B.:  The KEY_NET_GET key call is undocumented.  Applications shouldn't
 * be using it, because it allows them to get the user's secret key.
 */
int
key_secretkey_is_set (void)
{
  struct key_netstres kres;

  memset (&kres, 0, sizeof (kres));
  if (key_call ((u_long) KEY_NET_GET, (xdrproc_t) xdr_void, (char *) NULL,
		(xdrproc_t) xdr_key_netstres, (char *) &kres) &&
      (kres.status == KEY_SUCCESS) &&
      (kres.key_netstres_u.knet.st_priv_key[0] != 0))
    {
      /* avoid leaving secret key in memory */
      memset (kres.key_netstres_u.knet.st_priv_key, 0, HEXKEYBYTES);
      return 1;
    }
  return 0;
}

int
key_encryptsession (char *remotename, des_block *deskey)
{
  cryptkeyarg arg;
  cryptkeyres res;

  arg.remotename = remotename;
  arg.deskey = *deskey;
  if (!key_call ((u_long) KEY_ENCRYPT, (xdrproc_t) xdr_cryptkeyarg,
		 (char *) &arg, (xdrproc_t) xdr_cryptkeyres, (char *) &res))
    return -1;

  if (res.status != KEY_SUCCESS)
    {
      debug ("encrypt status is nonzero");
      return -1;
    }
  *deskey = res.cryptkeyres_u.deskey;
  return 0;
}

int
key_decryptsession (char *remotename, des_block *deskey)
{
  cryptkeyarg arg;
  cryptkeyres res;

  arg.remotename = remotename;
  arg.deskey = *deskey;
  if (!key_call ((u_long) KEY_DECRYPT, (xdrproc_t) xdr_cryptkeyarg,
		 (char *) &arg, (xdrproc_t) xdr_cryptkeyres, (char *) &res))
    return -1;
  if (res.status != KEY_SUCCESS)
    {
      debug ("decrypt status is nonzero");
      return -1;
    }
  *deskey = res.cryptkeyres_u.deskey;
  return 0;
}

int
key_encryptsession_pk (char *remotename, netobj *remotekey,
		       des_block *deskey)
{
  cryptkeyarg2 arg;
  cryptkeyres res;

  arg.remotename = remotename;
  arg.remotekey = *remotekey;
  arg.deskey = *deskey;
  if (!key_call ((u_long) KEY_ENCRYPT_PK, (xdrproc_t) xdr_cryptkeyarg2,
		 (char *) &arg, (xdrproc_t) xdr_cryptkeyres, (char *) &res))
    return -1;

  if (res.status != KEY_SUCCESS)
    {
      debug ("encrypt status is nonzero");
      return -1;
    }
  *deskey = res.cryptkeyres_u.deskey;
  return 0;
}

int
key_decryptsession_pk (char *remotename, netobj *remotekey,
		       des_block *deskey)
{
  cryptkeyarg2 arg;
  cryptkeyres res;

  arg.remotename = remotename;
  arg.remotekey = *remotekey;
  arg.deskey = *deskey;
  if (!key_call ((u_long) KEY_DECRYPT_PK, (xdrproc_t) xdr_cryptkeyarg2,
		 (char *) &arg, (xdrproc_t) xdr_cryptkeyres, (char *) &res))
    return -1;

  if (res.status != KEY_SUCCESS)
    {
      debug ("decrypt status is nonzero");
      return -1;
    }
  *deskey = res.cryptkeyres_u.deskey;
  return 0;
}

int
key_gendes (des_block *key)
{
  struct sockaddr_in sin;
  CLIENT *client;
  int socket;
  enum clnt_stat stat;

  sin.sin_family = AF_INET;
  sin.sin_port = 0;
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  bzero (sin.sin_zero, sizeof (sin.sin_zero));
  socket = RPC_ANYSOCK;
  client = clntudp_bufcreate (&sin, (u_long) KEY_PROG, (u_long) KEY_VERS,
			      trytimeout, &socket, RPCSMALLMSGSIZE,
			      RPCSMALLMSGSIZE);
  if (client == NULL)
    return -1;

  stat = clnt_call (client, KEY_GEN, (xdrproc_t) xdr_void, NULL,
		    (xdrproc_t) xdr_des_block, (caddr_t) key, tottimeout);
  clnt_destroy (client);
  close (socket);
  if (stat != RPC_SUCCESS)
    return -1;

  return 0;
}

int
key_setnet (struct key_netstarg *arg)
{
  keystatus status;

  if (!key_call ((u_long) KEY_NET_PUT, (xdrproc_t) xdr_key_netstarg,
		 (char *) arg,(xdrproc_t) xdr_keystatus, (char *) &status))
    return -1;

  if (status != KEY_SUCCESS)
    {
      debug ("key_setnet status is nonzero");
      return -1;
    }
  return 1;
}

int
key_get_conv (char *pkey, des_block *deskey)
{
  cryptkeyres res;

  if (!key_call ((u_long) KEY_GET_CONV, (xdrproc_t) xdr_keybuf, pkey,
		 (xdrproc_t) xdr_cryptkeyres, (char *) &res))
    return -1;

  if (res.status != KEY_SUCCESS)
    {
      debug ("get_conv status is nonzero");
      return -1;
    }
  *deskey = res.cryptkeyres_u.deskey;
  return 0;
}

/*
 * Hack to allow the keyserver to use AUTH_DES (for authenticated
 * NIS+ calls, for example).  The only functions that get called
 * are key_encryptsession_pk, key_decryptsession_pk, and key_gendes.
 *
 * The approach is to have the keyserver fill in pointers to local
 * implementations of these functions, and to call those in key_call().
 */

cryptkeyres *(*__key_encryptsession_pk_LOCAL) (uid_t, char *) = 0;
cryptkeyres *(*__key_decryptsession_pk_LOCAL) (uid_t, char *) = 0;
des_block *(*__key_gendes_LOCAL) (uid_t, char *) = 0;

static int
key_call (u_long proc, xdrproc_t xdr_arg, char *arg,
	  xdrproc_t xdr_rslt, char *rslt)
{
  XDR xdrargs;
  XDR xdrrslt;
  FILE *fargs;
  FILE *frslt;
  sigset_t oldmask, mask;
  union wait status;
  int pid;
  int success;
  uid_t ruid;
  uid_t euid;
  static char MESSENGER[] = "/usr/etc/keyenvoy";

  if (proc == KEY_ENCRYPT_PK && __key_encryptsession_pk_LOCAL)
    {
      cryptkeyres *res;
      res = (*__key_encryptsession_pk_LOCAL) (geteuid (), arg);
      *(cryptkeyres *) rslt = *res;
      return 1;
    }
  else if (proc == KEY_DECRYPT_PK && __key_decryptsession_pk_LOCAL)
    {
      cryptkeyres *res;
      res = (*__key_decryptsession_pk_LOCAL) (geteuid (), arg);
      *(cryptkeyres *) rslt = *res;
      return 1;
    }
  else if (proc == KEY_GEN && __key_gendes_LOCAL)
    {
      des_block *res;
      res = (*__key_gendes_LOCAL) (geteuid (), 0);
      *(des_block *) rslt = *res;
      return 1;
    }

  success = 1;
  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);
  sigprocmask (SIG_BLOCK, &mask, &oldmask);

  /*
   * We are going to exec a set-uid program which makes our effective uid
   * zero, and authenticates us with our real uid. We need to make the
   * effective uid be the real uid for the setuid program, and
   * the real uid be the effective uid so that we can change things back.
   */
  euid = geteuid ();
  ruid = getuid ();
  setreuid (euid, ruid);
  pid = _openchild (MESSENGER, &fargs, &frslt);
  setreuid (ruid, euid);
  if (pid < 0)
    {
      debug ("open_streams");
      sigprocmask(SIG_SETMASK, &oldmask, NULL);
      return (0);
    }
  xdrstdio_create (&xdrargs, fargs, XDR_ENCODE);
  xdrstdio_create (&xdrrslt, frslt, XDR_DECODE);

  if (!xdr_u_long (&xdrargs, &proc) || !(*xdr_arg) (&xdrargs, arg))
    {
      debug ("xdr args");
      success = 0;
    }
  fclose (fargs);

  if (success && !(*xdr_rslt) (&xdrrslt, rslt))
    {
      debug ("xdr rslt");
      success = 0;
    }
  fclose(frslt);

 wait_again:
  if (wait4(pid, &status, 0, NULL) < 0)
    {
      if (errno == EINTR)
	goto wait_again;
      debug("wait4");
      if (errno == ECHILD || errno == ESRCH)
	perror("wait");
      else
	success = 0;
    }
  else
    if (status.w_retcode)
      {
	debug("wait4 1");
	success = 0;
      }
  sigprocmask(SIG_SETMASK, &oldmask, NULL);

  return (success);
}
