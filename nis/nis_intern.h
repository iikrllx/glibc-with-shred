/* Copyright (c) 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@suse.de>, 1997.

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

#ifndef __NIS_INTERN_H

#define __NIS_INTERN_H
#include <features.h>

__BEGIN_DECLS

struct nis_cb
  {
    nis_server *serv;
    SVCXPRT *xprt;
    int sock;
    int nomore;
    nis_error result;
    int (*callback) (const_nis_name, const nis_object *, const void *);
    const void *userdata;
  };
typedef struct nis_cb nis_cb;

extern unsigned long int inetstr2int (const char *str);
extern long int __nis_findfastest (dir_binding *bind);
extern nis_error __do_niscall2 (const nis_server *serv, u_int serv_len,
				u_long prog, xdrproc_t xargs, caddr_t req,
				xdrproc_t xres, caddr_t resp,
				unsigned int flags, nis_cb *cb);
extern nis_error __do_niscall (const_nis_name name, u_long prog,
			       xdrproc_t xargs, caddr_t req,
			       xdrproc_t xres, caddr_t resp,
			       unsigned int flags, nis_cb *cb);
extern nis_error __do_niscall3 (dir_binding *dbp, u_long prog,
				xdrproc_t xargs, caddr_t req,
				xdrproc_t xres, caddr_t resp,
				unsigned int flags, nis_cb *cb);

extern u_short __pmap_getnisport (struct sockaddr_in *address, u_long program,
				  u_long version, u_int protocol);

/* NIS+ callback */
extern nis_error __nis_do_callback (struct dir_binding *bptr,
				    netobj *cookie, struct nis_cb *cb);
extern struct nis_cb *__nis_create_callback
      (int (*callback)(const_nis_name, const nis_object *, const void *),
       const void *userdata, unsigned int flags);
extern nis_error __nis_destroy_callback (struct nis_cb *cb);

__END_DECLS

#endif
