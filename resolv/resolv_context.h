/* Temporary, thread-local resolver state.
   Copyright (C) 2017 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.  */

/* struct resolv_context objects are allocated on the heap,
   initialized by __resolv_context_get (and its variants), and
   destroyed by __resolv_context_put.

   A nested call to __resolv_context_get (after another call to
   __resolv_context_get without a matching __resolv_context_put call,
   on the same thread) returns the original pointer, instead of
   allocating a new context.  This prevents unexpected reloading of
   the resolver configuration.  Care is taken to keep the context in
   sync with the thread-local _res object.  (This does not happen with
   __resolv_context_get_override, and __resolv_context_get_no_inet6 may
   also interpose another context object if RES_USE_INET6 needs to be
   disabled.)

   In contrast to struct __res_state, struct resolv_context is not
   affected by ABI compatibility concerns.

   For the benefit of the res_n* functions, a struct __res_state
   pointer is included in the context object, and a separate
   initialization function is provided.  */

#ifndef _RESOLV_CONTEXT_H
#define _RESOLV_CONTEXT_H

#include <bits/types/res_state.h>
#include <resolv/resolv_conf.h>
#include <stdbool.h>
#include <stddef.h>

/* Temporary resolver state.  */
struct resolv_context
{
  struct __res_state *resp;     /* Backing resolver state.   */

  /* Extended resolver state.  This is set to NULL if the
     __resolv_context_get functions are unable to locate an associated
     extended state.  In this case, the configuration data in *resp
     has to be used; otherwise, the data from *conf should be
     preferred (because it is a superset).  */
  struct resolv_conf *conf;

  /* The following fields are for internal use within the
     resolv_context module.  */
  size_t __refcount;            /* Count of reusages by the get functions.  */
  bool __from_res;              /* True if created from _res.  */

  /* If RES_USE_INET6 was disabled at this level, this field points to
     the previous context.  */
  struct resolv_context *__next;
};

/* Return the current temporary resolver context, or NULL if there was
   an error (indicated by errno).  A call to this function must be
   paired with a call to __resolv_context_put.  */
struct resolv_context *__resolv_context_get (void)
  __attribute__ ((warn_unused_result));
libc_hidden_proto (__resolv_context_get)

/* Deallocate the temporary resolver context.  Converse of
   __resolv_context_get.  Restore the RES_USE_INET6 flag if necessary.
   Do nothing if CTX is NULL.  */
void __resolv_context_put (struct resolv_context *ctx);
libc_hidden_proto (__resolv_context_put)

/* Like __resolv_context_get, but the _res structure can be partially
   initialzed and those changes will not be overwritten.  */
struct resolv_context *__resolv_context_get_preinit (void)
  __attribute__ ((warn_unused_result));
libc_hidden_proto (__resolv_context_get_preinit)

/* Wrap a struct __res_state object in a struct resolv_context object.
   A call to this function must be paired with a call to
   __resolv_context_put.  */
struct resolv_context *__resolv_context_get_override (struct __res_state *)
  __attribute__ ((nonnull (1), warn_unused_result));
libc_hidden_proto (__resolv_context_get_override)

/* Called during thread shutdown to free the associated resolver
   context (mostly in response to cancellation, otherwise the
   __resolv_context_get/__resolv_context_put pairing will already have
   deallocated the context object).  */
void __resolv_context_freeres (void) attribute_hidden;

#endif /* _RESOLV_CONTEXT_H */
