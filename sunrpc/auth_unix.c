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
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */
/*
 * auth_unix.c, Implements UNIX style authentication parameters.
 *
 * The system is very weak.  The client uses no encryption for it's
 * credentials and only sends null verifiers.  The server sends backs
 * null verifiers or optionally a verifier that suggests a new short hand
 * for the credentials.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/param.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>

#ifdef USE_IN_LIBIO
# include <wchar.h>
#endif

/*
 * Unix authenticator operations vector
 */
static void authunix_nextverf (AUTH *);
static bool_t authunix_marshal (AUTH *, XDR *);
static bool_t authunix_validate (AUTH *, struct opaque_auth *);
static bool_t authunix_refresh (AUTH *);
static void authunix_destroy (AUTH *);

static struct auth_ops auth_unix_ops = {
  authunix_nextverf,
  authunix_marshal,
  authunix_validate,
  authunix_refresh,
  authunix_destroy
};

/*
 * This struct is pointed to by the ah_private field of an auth_handle.
 */
struct audata {
  struct opaque_auth au_origcred;	/* original credentials */
  struct opaque_auth au_shcred;	/* short hand cred */
  u_long au_shfaults;		/* short hand cache faults */
  char au_marshed[MAX_AUTH_BYTES];
  u_int au_mpos;		/* xdr pos at end of marshed */
};
#define	AUTH_PRIVATE(auth)	((struct audata *)auth->ah_private)

static bool_t marshal_new_auth (AUTH *) internal_function;


/*
 * Create a unix style authenticator.
 * Returns an auth handle with the given stuff in it.
 */
AUTH *
authunix_create (char *machname, uid_t uid, gid_t gid, int len,
		 gid_t *aup_gids)
{
  struct authunix_parms aup;
  char mymem[MAX_AUTH_BYTES];
  struct timeval now;
  XDR xdrs;
  AUTH *auth;
  struct audata *au;

  /*
   * Allocate and set up auth handle
   */
  auth = (AUTH *) mem_alloc (sizeof (*auth));
  au = (struct audata *) mem_alloc (sizeof (*au));
  if (auth == NULL || au == NULL)
    {
no_memory:
      (void) __fxprintf (NULL, "%s", _("authunix_create: out of memory\n"));
      mem_free (auth, sizeof (*auth));
      mem_free (au, sizeof (*au));
      return NULL;
    }
  auth->ah_ops = &auth_unix_ops;
  auth->ah_private = (caddr_t) au;
  auth->ah_verf = au->au_shcred = _null_auth;
  au->au_shfaults = 0;

  /*
   * fill in param struct from the given params
   */
  (void) __gettimeofday (&now, (struct timezone *) 0);
  aup.aup_time = now.tv_sec;
  aup.aup_machname = machname;
  aup.aup_uid = uid;
  aup.aup_gid = gid;
  aup.aup_len = (u_int) len;
  aup.aup_gids = aup_gids;

  /*
   * Serialize the parameters into origcred
   */
  INTUSE(xdrmem_create) (&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
  if (!INTUSE(xdr_authunix_parms) (&xdrs, &aup))
    abort ();
  au->au_origcred.oa_length = len = XDR_GETPOS (&xdrs);
  au->au_origcred.oa_flavor = AUTH_UNIX;
  au->au_origcred.oa_base = mem_alloc ((u_int) len);
  if (au->au_origcred.oa_base == NULL)
    goto no_memory;
  memcpy(au->au_origcred.oa_base, mymem, (u_int) len);

  /*
   * set auth handle to reflect new cred.
   */
  auth->ah_cred = au->au_origcred;
  marshal_new_auth (auth);
  return auth;
}
INTDEF (authunix_create)

/*
 * Returns an auth handle with parameters determined by doing lots of
 * syscalls.
 */
AUTH *
authunix_create_default (void)
{
  char machname[MAX_MACHINE_NAME + 1];

  if (__gethostname (machname, MAX_MACHINE_NAME) == -1)
    abort ();
  machname[MAX_MACHINE_NAME] = 0;
  uid_t uid = __geteuid ();
  gid_t gid = __getegid ();

  int max_nr_groups;
  /* When we have to try a second time, do not use alloca() again.  We
     might have reached the stack limit already.  */
  bool retry = false;
 again:
  /* Ask the kernel how many groups there are exactly.  Note that we
     might have to redo all this if the number of groups has changed
     between the two calls.  */
  max_nr_groups = __getgroups (0, NULL);

  /* Just some random reasonable stack limit.  */
#define ALLOCA_LIMIT (1024 / sizeof (gid_t))
  gid_t *gids = NULL;
  if (max_nr_groups < ALLOCA_LIMIT && ! retry)
    gids = (gid_t *) alloca (max_nr_groups * sizeof (gid_t));
  else
    {
      gids = (gid_t *) malloc (max_nr_groups * sizeof (gid_t));
      if (gids == NULL)
	return NULL;
    }

  int len = __getgroups (max_nr_groups, gids);
  if (len == -1)
    {
      if (errno == EINVAL)
	{
	  /* New groups added in the meantime.  Try again.  */
	  if (max_nr_groups >= ALLOCA_LIMIT || retry)
	    free (gids);
	  retry = true;
	  goto again;
	}
      /* No other error can happen.  */
      abort ();
    }

  /* This braindamaged Sun code forces us here to truncate the
     list of groups to NGRPS members since the code in
     authuxprot.c transforms a fixed array.  Grrr.  */
  AUTH *result = INTUSE(authunix_create) (machname, uid, gid, MIN (NGRPS, len),
					  gids);

  if (max_nr_groups >= ALLOCA_LIMIT || retry)
    free (gids);

  return result;
}
INTDEF (authunix_create_default)

/*
 * authunix operations
 */

static void
authunix_nextverf (AUTH *auth)
{
  /* no action necessary */
}

static bool_t
authunix_marshal (AUTH *auth, XDR *xdrs)
{
  struct audata *au = AUTH_PRIVATE (auth);

  return XDR_PUTBYTES (xdrs, au->au_marshed, au->au_mpos);
}

static bool_t
authunix_validate (AUTH *auth, struct opaque_auth *verf)
{
  struct audata *au;
  XDR xdrs;

  if (verf->oa_flavor == AUTH_SHORT)
    {
      au = AUTH_PRIVATE (auth);
      INTUSE(xdrmem_create) (&xdrs, verf->oa_base, verf->oa_length,
			     XDR_DECODE);

      if (au->au_shcred.oa_base != NULL)
	{
	  mem_free (au->au_shcred.oa_base,
		    au->au_shcred.oa_length);
	  au->au_shcred.oa_base = NULL;
	}
      if (INTUSE(xdr_opaque_auth) (&xdrs, &au->au_shcred))
	{
	  auth->ah_cred = au->au_shcred;
	}
      else
	{
	  xdrs.x_op = XDR_FREE;
	  (void) INTUSE(xdr_opaque_auth) (&xdrs, &au->au_shcred);
	  au->au_shcred.oa_base = NULL;
	  auth->ah_cred = au->au_origcred;
	}
      marshal_new_auth (auth);
    }
  return TRUE;
}

static bool_t
authunix_refresh (AUTH *auth)
{
  struct audata *au = AUTH_PRIVATE (auth);
  struct authunix_parms aup;
  struct timeval now;
  XDR xdrs;
  int stat;

  if (auth->ah_cred.oa_base == au->au_origcred.oa_base)
    {
      /* there is no hope.  Punt */
      return FALSE;
    }
  au->au_shfaults++;

  /* first deserialize the creds back into a struct authunix_parms */
  aup.aup_machname = NULL;
  aup.aup_gids = (gid_t *) NULL;
  INTUSE(xdrmem_create) (&xdrs, au->au_origcred.oa_base,
			 au->au_origcred.oa_length, XDR_DECODE);
  stat = INTUSE(xdr_authunix_parms) (&xdrs, &aup);
  if (!stat)
    goto done;

  /* update the time and serialize in place */
  (void) __gettimeofday (&now, (struct timezone *) 0);
  aup.aup_time = now.tv_sec;
  xdrs.x_op = XDR_ENCODE;
  XDR_SETPOS (&xdrs, 0);
  stat = INTUSE(xdr_authunix_parms) (&xdrs, &aup);
  if (!stat)
    goto done;
  auth->ah_cred = au->au_origcred;
  marshal_new_auth (auth);
done:
  /* free the struct authunix_parms created by deserializing */
  xdrs.x_op = XDR_FREE;
  (void) INTUSE(xdr_authunix_parms) (&xdrs, &aup);
  XDR_DESTROY (&xdrs);
  return stat;
}

static void
authunix_destroy (AUTH *auth)
{
  struct audata *au = AUTH_PRIVATE (auth);

  mem_free (au->au_origcred.oa_base, au->au_origcred.oa_length);

  if (au->au_shcred.oa_base != NULL)
    mem_free (au->au_shcred.oa_base, au->au_shcred.oa_length);

  mem_free (auth->ah_private, sizeof (struct audata));

  if (auth->ah_verf.oa_base != NULL)
    mem_free (auth->ah_verf.oa_base, auth->ah_verf.oa_length);

  mem_free ((caddr_t) auth, sizeof (*auth));
}

/*
 * Marshals (pre-serializes) an auth struct.
 * sets private data, au_marshed and au_mpos
 */
static bool_t
internal_function
marshal_new_auth (AUTH *auth)
{
  XDR xdr_stream;
  XDR *xdrs = &xdr_stream;
  struct audata *au = AUTH_PRIVATE (auth);

  INTUSE(xdrmem_create) (xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
  if ((!INTUSE(xdr_opaque_auth) (xdrs, &(auth->ah_cred))) ||
      (!INTUSE(xdr_opaque_auth) (xdrs, &(auth->ah_verf))))
    perror (_("auth_none.c - Fatal marshalling problem"));
  else
    au->au_mpos = XDR_GETPOS (xdrs);

  XDR_DESTROY (xdrs);

  return TRUE;
}
