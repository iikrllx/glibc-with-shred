#ifndef _RPC_SVC_H
#include <sunrpc/rpc/svc.h>

/* Now define the internal interfaces.  */
extern int registerrpc (u_long prognum, u_long versnum, u_long procnum,
			char *(*progname) (char *), xdrproc_t inproc,
			xdrproc_t outproc);

extern SVCXPRT *svcfd_create (int fd, u_int sendsize, u_int recvsize);

extern int svcudp_enablecache (SVCXPRT *transp, u_long size);
extern SVCXPRT *svcunixfd_create (int fd, u_int sendsize, u_int recvsize);
extern bool_t svc_sendreply_internal (SVCXPRT *xprt, xdrproc_t __xdr_results,
				      caddr_t __xdr_location) attribute_hidden;
extern void svcerr_decode_internal (SVCXPRT *__xprt) attribute_hidden;
extern void svc_getreq_internal (int __rdfds) attribute_hidden;
extern void svc_getreq_common_internal (const int __fd) attribute_hidden;
extern void svc_getreqset_internal (fd_set *__readfds) attribute_hidden;
extern void svc_getreq_poll_internal (struct pollfd *,
				      const int) attribute_hidden;
extern bool_t svc_register_internal (SVCXPRT *__xprt, rpcprog_t __prog,
				     rpcvers_t __vers,
				     __dispatch_fn_t __dispatch,
				     rpcprot_t __protocol) attribute_hidden;
extern void svc_unregister_internal (rpcprog_t __prog,
				     rpcvers_t __vers) attribute_hidden;
extern SVCXPRT *svcudp_create_internal (int __sock) attribute_hidden;
extern SVCXPRT *svcudp_bufcreate_internal (int __sock, u_int __sendsz,
					   u_int __recvsz) attribute_hidden;

#endif
