/* @(#)xdr.h	2.2 88/07/29 4.0 RPCSRC */
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
/*      @(#)xdr.h 1.19 87/04/22 SMI      */

/*
 * xdr.h, External Data Representation Serialization Routines.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef _RPC_XDR_H
#define _RPC_XDR_H 1

#include <features.h>
#include <sys/types.h>
#include <rpc/types.h>

/* We need FILE.  */
#include <stdio.h>

__BEGIN_DECLS

/*
 * XDR provides a conventional way for converting between C data
 * types and an external bit-string representation.  Library supplied
 * routines provide for the conversion on built-in C data types.  These
 * routines and utility routines defined here are used to help implement
 * a type encode/decode routine for each user-defined type.
 *
 * Each data type provides a single procedure which takes two arguments:
 *
 *      bool_t
 *      xdrproc(xdrs, argresp)
 *              XDR *xdrs;
 *              <type> *argresp;
 *
 * xdrs is an instance of a XDR handle, to which or from which the data
 * type is to be converted.  argresp is a pointer to the structure to be
 * converted.  The XDR handle contains an operation field which indicates
 * which of the operations (ENCODE, DECODE * or FREE) is to be performed.
 *
 * XDR_DECODE may allocate space if the pointer argresp is null.  This
 * data can be freed with the XDR_FREE operation.
 *
 * We write only one procedure per data type to make it easy
 * to keep the encode and decode procedures for a data type consistent.
 * In many cases the same code performs all operations on a user defined type,
 * because all the hard work is done in the component type routines.
 * decode as a series of calls on the nested data types.
 */

/*
 * Xdr operations.  XDR_ENCODE causes the type to be encoded into the
 * stream.  XDR_DECODE causes the type to be extracted from the stream.
 * XDR_FREE can be used to release the space allocated by an XDR_DECODE
 * request.
 */
enum xdr_op
  {
    XDR_ENCODE = 0,
    XDR_DECODE = 1,
    XDR_FREE = 2
  };

/*
 * This is the number of bytes per unit of external data.
 */
#define BYTES_PER_XDR_UNIT	(4)
/*
 * This only works if the above is a power of 2.  But it's defined to be
 * 4 by the appropriate RFCs.  So it will work.  And it's normally quicker
 * than the old routine.
 */
#if 1
#define RNDUP(x)  (((x) + BYTES_PER_XDR_UNIT - 1) & ~(BYTES_PER_XDR_UNIT - 1))
#else /* this is the old routine */
#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
		    * BYTES_PER_XDR_UNIT)
#endif

/*
 * The XDR handle.
 * Contains operation which is being applied to the stream,
 * an operations vector for the particular implementation (e.g. see xdr_mem.c),
 * and two private fields for the use of the particular implementation.
 */
typedef struct XDR XDR;
struct XDR
  {
    enum xdr_op x_op;		/* operation; fast additional param */
    const struct xdr_ops
      {
	bool_t (*x_getlong) __P ((XDR * __xdrs, long *__lp));
	/* get a long from underlying stream */
	bool_t (*x_putlong) __P ((XDR * __xdrs, __const long *__lp));
	/* put a long to " */
	bool_t (*x_getbytes) __P ((XDR * __xdrs, caddr_t __addr, u_int __len));
	/* get some bytes from " */
	bool_t (*x_putbytes) __P ((XDR * __xdrs, __const char *__addr,
				   u_int __len));
	/* put some bytes to " */
	u_int (*x_getpostn) __P ((__const XDR * __xdrs));
	/* returns bytes off from beginning */
	bool_t (*x_setpostn) __P ((XDR * __xdrs, u_int pos));
	/* lets you reposition the stream */
	long *(*x_inline) __P ((XDR * __xdrs, int len));
	/* buf quick ptr to buffered data */
	void (*x_destroy) __P ((__const XDR * __xdrs));
	/* free privates of this xdr_stream */
      }
     *x_ops;
    caddr_t x_public;		/* users' data */
    caddr_t x_private;		/* pointer to private data */
    caddr_t x_base;		/* private used for position info */
    int x_handy;		/* extra private word */
  };

/*
 * A xdrproc_t exists for each data type which is to be encoded or decoded.
 *
 * The second argument to the xdrproc_t is a pointer to an opaque pointer.
 * The opaque pointer generally points to a structure of the data type
 * to be decoded.  If this pointer is 0, then the type routines should
 * allocate dynamic storage of the appropriate size and return it.
 * bool_t       (*xdrproc_t)(XDR *, caddr_t *);
 */
typedef
bool_t (*xdrproc_t) __P ((XDR *, void *,...));

/*
 * Operations defined on a XDR handle
 *
 * XDR          *xdrs;
 * long         *longp;
 * caddr_t       addr;
 * u_int         len;
 * u_int         pos;
 */
#define XDR_GETLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define xdr_getlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)

#define XDR_PUTLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define xdr_putlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)

#define XDR_GETBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define xdr_getbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)

#define XDR_PUTBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define xdr_putbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)

#define XDR_GETPOS(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)
#define xdr_getpos(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)

#define XDR_SETPOS(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
#define xdr_setpos(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)

#define	XDR_INLINE(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)
#define	xdr_inline(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)

#define	XDR_DESTROY(xdrs)				\
	if ((xdrs)->x_ops->x_destroy) 			\
		(*(xdrs)->x_ops->x_destroy)(xdrs)
#define	xdr_destroy(xdrs)				\
	if ((xdrs)->x_ops->x_destroy) 			\
		(*(xdrs)->x_ops->x_destroy)(xdrs)

/*
 * Support struct for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * a entry with a null procedure pointer.  The xdr_union routine gets
 * the discriminant value and then searches the array of structures
 * for a matching value.  If a match is found the associated xdr routine
 * is called to handle that part of the union.  If there is
 * no match, then a default routine may be called.
 * If there is no match and no default routine it is an error.
 */
#define NULL_xdrproc_t ((xdrproc_t)0)
struct xdr_discrim
{
  int value;
  xdrproc_t proc;
};

/*
 * Inline routines for fast encode/decode of primitive data types.
 * Caveat emptor: these use single memory cycles to get the
 * data from the underlying buffer, and will fail to operate
 * properly if the data is not aligned.  The standard way to use these
 * is to say:
 *      if ((buf = XDR_INLINE(xdrs, count)) == NULL)
 *              return (FALSE);
 *      <<< macro calls >>>
 * where ``count'' is the number of bytes of data occupied
 * by the primitive data types.
 *
 * N.B. and frozen for all time: each data type here uses 4 bytes
 * of external representation.
 */
#define IXDR_GET_LONG(buf)		((long)ntohl((u_long)*((u_int32_t*)buf)++))
#define IXDR_PUT_LONG(buf, v)		(*((u_int32_t*)(buf))++ = (long)htonl((u_long)v))

#define IXDR_GET_BOOL(buf)		((bool_t)IXDR_GET_LONG(buf))
#define IXDR_GET_ENUM(buf, t)		((t)IXDR_GET_LONG(buf))
#define IXDR_GET_U_LONG(buf)		((u_long)IXDR_GET_LONG(buf))
#define IXDR_GET_SHORT(buf)		((short)IXDR_GET_LONG(buf))
#define IXDR_GET_U_SHORT(buf)		((u_short)IXDR_GET_LONG(buf))

#define IXDR_PUT_BOOL(buf, v)		IXDR_PUT_LONG((buf), ((long)(v)))
#define IXDR_PUT_ENUM(buf, v)		IXDR_PUT_LONG((buf), ((long)(v)))
#define IXDR_PUT_U_LONG(buf, v)		IXDR_PUT_LONG((buf), ((long)(v)))
#define IXDR_PUT_SHORT(buf, v)		IXDR_PUT_LONG((buf), ((long)(v)))
#define IXDR_PUT_U_SHORT(buf, v)	IXDR_PUT_LONG((buf), ((long)(v)))

/*
 * These are the "generic" xdr routines.
 * None of these can have const applied because it's not possible to
 * know whether the call is a read or a write to the passed parameter
 * also, the XDR structure is always updated by some of these calls.
 */
extern bool_t xdr_void __P ((void));
extern bool_t xdr_int __P ((XDR * __xdrs, int *__ip));
extern bool_t xdr_u_int __P ((XDR * __xdrs, u_int * __up));
extern bool_t xdr_long __P ((XDR * __xdrs, long *__lp));
extern bool_t xdr_u_long __P ((XDR * __xdrs, u_long * __ulp));
extern bool_t xdr_short __P ((XDR * __xdrs, short *__sp));
extern bool_t xdr_u_short __P ((XDR * __xdrs, u_short * __usp));
extern bool_t xdr_bool __P ((XDR * __xdrs, bool_t * __bp));
extern bool_t xdr_enum __P ((XDR * __xdrs, enum_t * __ep));
extern bool_t xdr_array __P ((XDR * _xdrs, caddr_t * __addrp, u_int * __sizep,
			      u_int __maxsize, u_int __elsize,
			      xdrproc_t __elproc));
extern bool_t xdr_bytes __P ((XDR * __xdrs, char **__cpp, u_int * __sizep,
			      u_int __maxsize));
extern bool_t xdr_opaque __P ((XDR * __xdrs, caddr_t __cp, u_int __cnt));
extern bool_t xdr_string __P ((XDR * __xdrs, char **__cpp, u_int __maxsize));
extern bool_t xdr_union __P ((XDR * __xdrs, enum_t * __dscmp, char *__unp,
			      __const struct xdr_discrim * __choices,
			      xdrproc_t dfault));
extern bool_t xdr_char __P ((XDR * __xdrs, char *__cp));
extern bool_t xdr_u_char __P ((XDR * __xdrs, u_char * __cp));
extern bool_t xdr_vector __P ((XDR * __xdrs, char *__basep, u_int __nelem,
			       u_int __elemsize, xdrproc_t __xdr_elem));
extern bool_t xdr_float __P ((XDR * __xdrs, float *__fp));
extern bool_t xdr_double __P ((XDR * __xdrs, double *__dp));
extern bool_t xdr_reference __P ((XDR * __xdrs, caddr_t * __pp, u_int __size,
				  xdrproc_t __proc));
extern bool_t xdr_pointer __P ((XDR * __xdrs, char **__objpp,
				u_int __obj_size, xdrproc_t __xdr_obj));
extern bool_t xdr_wrapstring __P ((XDR * __xdrs, char **__cpp));
extern u_long xdr_sizeof __P ((xdrproc_t, void *));

/*
 * Common opaque bytes objects used by many rpc protocols;
 * declared here due to commonality.
 */
#define MAX_NETOBJ_SZ 1024
struct netobj
{
  u_int n_len;
  char *n_bytes;
};
typedef struct netobj netobj;
extern bool_t xdr_netobj __P ((XDR * __xdrs, struct netobj * __np));

/*
 * These are the public routines for the various implementations of
 * xdr streams.
 */

/* XDR using memory buffers */
extern void xdrmem_create __P ((XDR * __xdrs, __const caddr_t __addr,
				u_int __size, enum xdr_op __op));

/* XDR using stdio library */
extern void xdrstdio_create __P ((XDR * __xdrs, FILE * __file,
				  enum xdr_op __op));

/* XDR pseudo records for tcp */
extern void xdrrec_create __P ((XDR * __xdrs, u_int __sendsize,
				u_int __recvsize, caddr_t __tcp_handle,
				int (*__readit) (char *, char *, int),
				int (*__writeit) (char *, char *, int)));

/* make end of xdr record */
extern bool_t xdrrec_endofrecord __P ((XDR * __xdrs, bool_t __sendnow));

/* move to beginning of next record */
extern bool_t xdrrec_skiprecord __P ((XDR * __xdrs));

/* true if no more input */
extern bool_t xdrrec_eof __P ((XDR * __xdrs));

/* free memory buffers for xdr */
extern void xdr_free __P ((xdrproc_t __proc, char *__objp));

__END_DECLS

#endif /* rpc/xdr.h */
