/* Copyright (c) 1997, 1998 Free Software Foundation, Inc.
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
#include <rpcsvc/nis.h>
#include "nis_intern.h"

static void
splitname (const_nis_name name, nis_name *ibr_name, int *srch_len,
	   nis_attr **srch_val)
{
  char *cptr, *key, *val, *next;
  int size;

  if (name == NULL)
    return;

  cptr = strdup (name);
  if (srch_len)
    *srch_len = 0;
  if (srch_val)
    *srch_val = NULL;
  size = 0;

  /* Not of "[key=value,key=value,...],foo.." format? */
  if (cptr[0] != '[')
    {
      *ibr_name = cptr;
      return;
    }

  *ibr_name = strchr (cptr, ']');
  if (*ibr_name == NULL || (*ibr_name)[1] != ',')
    {
      free (cptr);
      *ibr_name = NULL;
      return;
    }

  *ibr_name[0] = '\0';
  *ibr_name += 2;
  *ibr_name = strdup (*ibr_name);

  if (srch_len == NULL || srch_val == NULL)
    {
      free (cptr);
      return;
    }

  key = (cptr) + 1;
  do
    {
      next = strchr (key, ',');
      if (next)
	{
	  next[0] = '\0';
	  ++next;
	}

      val = strchr (key, '=');
      if (!val)
	{
	  free (cptr);
	  *srch_val = malloc (sizeof (nis_attr));
	  if (*srch_val == NULL)
	    {
	      free (cptr);
	      free (*ibr_name);
	      *ibr_name = NULL;
	      return;
	    }
	  (*srch_val)[0].zattr_val.zattr_val_len = 0;
	  (*srch_val)[0].zattr_val.zattr_val_val = NULL;
	  return;
	}

      val[0] = '\0';
      ++val;

      if ((*srch_len) + 1 >= size)
	{
	  size += 10;
	  if (size == 10)
	    *srch_val = malloc (size * sizeof (char *));
	  else
	    *srch_val = realloc (val, size * sizeof (char *));
	  if (*srch_val == NULL)
	    {
	      free (cptr);
	      free (*ibr_name);
	      *ibr_name = NULL;
	      return;
	    }
	}

      (*srch_val)[*srch_len].zattr_ndx = strdup (key);
      if (((*srch_val)[*srch_len].zattr_ndx) == NULL)
	{
	  free (cptr);
	  free (*ibr_name);
	  *ibr_name = NULL;
	  return;
	}
      (*srch_val)[*srch_len].zattr_val.zattr_val_len = strlen (val) + 1;
      (*srch_val)[*srch_len].zattr_val.zattr_val_val = strdup (val);
      if ((*srch_val)[*srch_len].zattr_val.zattr_val_val == NULL)
	{
	  free (cptr);
	  free (*ibr_name);
	  *ibr_name = NULL;
	  return;
	}
      ++(*srch_len);

      key = next;

    }
  while (next);

  free (cptr);
}

static struct ib_request *
__create_ib_request (const_nis_name name, struct ib_request *ibreq,
		     u_long flags)
{
  splitname (name, &ibreq->ibr_name, &ibreq->ibr_srch.ibr_srch_len,
	     &ibreq->ibr_srch.ibr_srch_val);
  if (ibreq->ibr_name == NULL)
    return NULL;

  ibreq->ibr_flags = flags;
  ibreq->ibr_obj.ibr_obj_len = 0;
  ibreq->ibr_obj.ibr_obj_val = NULL;
  ibreq->ibr_cbhost.ibr_cbhost_len = 0;
  ibreq->ibr_cbhost.ibr_cbhost_val = NULL;
  ibreq->ibr_bufsize = 0;
  ibreq->ibr_cookie.n_len = 0;
  ibreq->ibr_cookie.n_bytes = NULL;

  return ibreq;
}

nis_result *
nis_list (const_nis_name name, u_long flags,
	  int (*callback) (const_nis_name name,
			   const nis_object *object,
			   const void *userdata),
	  const void *userdata)
{
  nis_result *res = NULL;
  ib_request *ibreq = calloc (1, sizeof (ib_request));
  int status;
  int count_links = 0;		/* We will only follow NIS_MAXLINKS links! */
  int done = 0;
  nis_name *names;
  nis_name namebuf[2] = {NULL, NULL};
  int name_nr = 0;
  nis_cb *cb = NULL;

  res = calloc (1, sizeof (nis_result));

  if (__create_ib_request (name, ibreq, flags) == NULL)
    {
      res->status = NIS_BADNAME;
      return res;
    }

  if (flags & EXPAND_NAME)
    {
      names = nis_getnames (ibreq->ibr_name);
      free (ibreq->ibr_name);
      ibreq->ibr_name = NULL;
      if (names == NULL)
	{
	  res->status = NIS_BADNAME;
	  return res;
	}
      ibreq->ibr_name = strdup (names[name_nr]);
    }
  else
    {
      names = namebuf;
      names[name_nr] = ibreq->ibr_name;
    }

  cb = NULL;

  if (flags & FOLLOW_PATH || flags & ALL_RESULTS)
    {
      nis_result *lres;
      u_long newflags = flags & ~FOLLOW_PATH & ~ALL_RESULTS;
      char table_path[NIS_MAXPATH + 1];
      char *ntable, *p;
      u_long done = 0, failures = 0;

      memset (res, '\0', sizeof (nis_result));

      while (names[name_nr] != NULL && !done)
	{
	  lres = nis_lookup (names[name_nr], newflags);
	  if (lres == NULL || lres->status != NIS_SUCCESS)
	    {
	      res->status = lres->status;
	      nis_freeresult (lres);
	      ++name_nr;
	      continue;
	      }

	  /* nis_lookup handles FOLLOW_LINKS,
	     so we must have a table object.  */
	  if (__type_of (NIS_RES_OBJECT (lres)) != NIS_TABLE_OBJ)
	    {
	      nis_freeresult (lres);
	      res->status = NIS_INVALIDOBJ;
	      break;
	    }

	  /* Save the path, discard everything else.  */
	  snprintf (table_path, NIS_MAXPATH, "%s:%s", names[name_nr],
		    NIS_RES_OBJECT (lres)->TA_data.ta_path);
	  nis_freeresult (lres);
	  free (res);
	  res = NULL;

	  p = table_path;

	  while (((ntable = strsep (&p, ":")) != NULL) && !done)
	    {
	      char *c;

	      if (res != NULL)
		nis_freeresult (res);

	      /* Do the job recursive here!  */
	      if ((c = strchr(name, ']')) != NULL)
		{
		  /* Have indexed name ! */
		  int index_len = c - name + 2;
		  char buf[index_len + strlen (ntable) + 1];

		  c = __stpncpy (buf, name, index_len);
		  strcpy (c, ntable);
		  res = nis_list (buf, newflags, callback,userdata);
		}
	      else
		res = nis_list (ntable, newflags, callback, userdata);
	      if (res == NULL)
		return NULL;
	      switch (res->status)
		{
		case NIS_SUCCESS:
		case NIS_CBRESULTS:
		  if (!(flags & ALL_RESULTS))
		    done = 1;
		  break;
		case NIS_PARTIAL: /* The table is correct, we doesn't found
				     the entry */
		  break;
		default:
		  if (flags & ALL_RESULTS)
		    ++failures;
		  else
		    done = 1;
		  break;
		}
	    }
	  if (res->status == NIS_SUCCESS && failures)
	    res->status = NIS_S_SUCCESS;
	  if (res->status == NIS_NOTFOUND && failures)
	    res->status = NIS_S_NOTFOUND;
	  break;
	}
    }
  else
    {
      if (callback != NULL)
	{
	  cb = __nis_create_callback (callback, userdata, flags);
	  ibreq->ibr_cbhost.ibr_cbhost_len = 1;
	  ibreq->ibr_cbhost.ibr_cbhost_val = cb->serv;
	  }

      while (!done)
	{
	  memset (res, '\0', sizeof (nis_result));

	  status = __do_niscall (ibreq->ibr_name, NIS_IBLIST,
				 (xdrproc_t) xdr_ib_request,
				 (caddr_t) ibreq, (xdrproc_t) xdr_nis_result,
				 (caddr_t) res, flags, cb);
	  if (status != NIS_SUCCESS)
	    res->status = status;

	  switch (res->status)
	    {
	    case NIS_PARTIAL:
	    case NIS_SUCCESS:
	    case NIS_S_SUCCESS:
	      if (__type_of (NIS_RES_OBJECT (res)) == NIS_LINK_OBJ &&
		  flags & FOLLOW_LINKS)		/* We are following links.  */
		{
		  /* If we hit the link limit, bail.  */
		  if (count_links > NIS_MAXLINKS)
		    {
		      res->status = NIS_LINKNAMEERROR;
		      ++done;
		      break;
		    }
		  if (count_links)
		    free (ibreq->ibr_name);
		  ++count_links;
		  free (ibreq->ibr_name);
		  ibreq->ibr_name =
		    strdup (NIS_RES_OBJECT (res)->LI_data.li_name);
		  if (NIS_RES_OBJECT (res)->LI_data.li_attrs.li_attrs_len)
		    if (ibreq->ibr_srch.ibr_srch_len == 0)
		      {
			ibreq->ibr_srch.ibr_srch_len =
			  NIS_RES_OBJECT (res)->LI_data.li_attrs.li_attrs_len;
			ibreq->ibr_srch.ibr_srch_val =
			  NIS_RES_OBJECT (res)->LI_data.li_attrs.li_attrs_val;
		      }
		  nis_freeresult (res);
		  res = calloc (1, sizeof (nis_result));
		}
	      else
		++done;
	      break;
	    case NIS_CBRESULTS:
	      /* Calback is handled in nis_call.c (__do_niscall2).  */
	      ++done;
	      break;
	    case NIS_UNAVAIL:
	      /* NIS+ is not installed, or all servers are down.  */
	      ++done;
	      break;
	    default:
	      /* Try the next domainname if we don't follow a link.  */
	      if (count_links)
		{
		  free (ibreq->ibr_name);
		  res->status = NIS_LINKNAMEERROR;
		  ++done;
		  break;
		}
	      ++name_nr;
	      if (names[name_nr] == NULL)
		{
		  ++done;
		  break;
		}
	      ibreq->ibr_name = names[name_nr];
	      break;
	    }
	}
    }				/* End of not FOLLOW_PATH.  */

  if (names != namebuf)
    nis_freenames (names);

  if (cb)
    {
      __nis_destroy_callback (cb);
      ibreq->ibr_cbhost.ibr_cbhost_len = 0;
      ibreq->ibr_cbhost.ibr_cbhost_val = NULL;
    }

  nis_free_request (ibreq);

  return res;
}

nis_result *
nis_add_entry (const_nis_name name, const nis_object *obj,
	       u_long flags)
{
  nis_result *res;
  nis_error status;
  ib_request *ibreq = calloc (1, sizeof (ib_request));
  char *p1, *p2, *p3, *p4;
  char buf1[strlen (name) + 20];
  char buf4[strlen (name) + 20];

  res = calloc (1, sizeof (nis_result));

  if (__create_ib_request (name, ibreq, flags) == NULL)
    {
      res->status = NIS_BADNAME;
      return res;
    }

  ibreq->ibr_obj.ibr_obj_val = nis_clone_object (obj, NULL);
  ibreq->ibr_obj.ibr_obj_len = 1;

  p1 = ibreq->ibr_obj.ibr_obj_val->zo_name;
  if (p1 == NULL || strlen (p1) == 0)
    ibreq->ibr_obj.ibr_obj_val->zo_name =
      nis_leaf_of_r (name, buf1, sizeof (buf1));

  p2 = ibreq->ibr_obj.ibr_obj_val->zo_owner;
  if (p2 == NULL || strlen (p2) == 0)
    ibreq->ibr_obj.ibr_obj_val->zo_owner = nis_local_principal ();

  p3 = ibreq->ibr_obj.ibr_obj_val->zo_group;
  if (p3 == NULL || strlen (p3) == 0)
    ibreq->ibr_obj.ibr_obj_val->zo_group = nis_local_group ();

  p4 = ibreq->ibr_obj.ibr_obj_val->zo_domain;
  ibreq->ibr_obj.ibr_obj_val->zo_domain =
    nis_domain_of_r (name, buf4, sizeof (buf4));

  if ((status = __do_niscall (ibreq->ibr_name, NIS_IBADD,
			      (xdrproc_t) xdr_ib_request,
			      (caddr_t) ibreq,
			      (xdrproc_t) xdr_nis_result,
			      (caddr_t) res, 0, NULL)) != NIS_SUCCESS)
    res->status = status;

  ibreq->ibr_obj.ibr_obj_val->zo_name = p1;
  ibreq->ibr_obj.ibr_obj_val->zo_owner = p2;
  ibreq->ibr_obj.ibr_obj_val->zo_group = p3;
  ibreq->ibr_obj.ibr_obj_val->zo_domain = p4;

  nis_free_request (ibreq);

  return res;
}

nis_result *
nis_modify_entry (const_nis_name name, const nis_object *obj,
		  u_long flags)
{
  nis_result *res;
  nis_error status;
  ib_request *ibreq = calloc (1, sizeof (ib_request));
  char *p1, *p2, *p3, *p4;
  char buf1[strlen (name) + 20];
  char buf4[strlen (name) + 20];

  res = calloc (1, sizeof (nis_result));

  if (__create_ib_request (name, ibreq, flags) == NULL)
    {
      res->status = NIS_BADNAME;
      return res;
    }

  ibreq->ibr_obj.ibr_obj_val = nis_clone_object (obj, NULL);
  ibreq->ibr_obj.ibr_obj_len = 1;

  p1 = ibreq->ibr_obj.ibr_obj_val->zo_name;
  if (p1 == NULL || strlen (p1) == 0)
    ibreq->ibr_obj.ibr_obj_val->zo_name =
      nis_leaf_of_r (name, buf1, sizeof (buf1));

  p2 = ibreq->ibr_obj.ibr_obj_val->zo_owner;
  if (p2 == NULL || strlen (p2) == 0)
    ibreq->ibr_obj.ibr_obj_val->zo_owner = nis_local_principal ();

  p3 = ibreq->ibr_obj.ibr_obj_val->zo_group;
  if (p3 == NULL || strlen (p3) == 0)
    ibreq->ibr_obj.ibr_obj_val->zo_group = nis_local_group ();

  p4 = ibreq->ibr_obj.ibr_obj_val->zo_domain;
  ibreq->ibr_obj.ibr_obj_val->zo_domain =
    nis_domain_of_r (name, buf4, sizeof (buf4));

  if ((status = __do_niscall (ibreq->ibr_name, NIS_IBMODIFY,
			      (xdrproc_t) xdr_ib_request,
			      (caddr_t) ibreq, (xdrproc_t) xdr_nis_result,
			      (caddr_t) res, 0, NULL)) != NIS_SUCCESS)
    res->status = status;

  ibreq->ibr_obj.ibr_obj_val->zo_name = p1;
  ibreq->ibr_obj.ibr_obj_val->zo_owner = p2;
  ibreq->ibr_obj.ibr_obj_val->zo_group = p3;
  ibreq->ibr_obj.ibr_obj_val->zo_domain = p4;

  nis_free_request (ibreq);

  return res;
}

nis_result *
nis_remove_entry (const_nis_name name, const nis_object *obj,
		  u_long flags)
{
  nis_result *res;
  ib_request *ibreq = calloc (1, sizeof (ib_request));
  nis_error status;

  res = calloc (1, sizeof (nis_result));

  if (__create_ib_request (name, ibreq, flags) == NULL)
    {
      res->status = NIS_BADNAME;
      return res;
    }

  if (obj != NULL)
    {
      ibreq->ibr_obj.ibr_obj_val = nis_clone_object (obj, NULL);
      ibreq->ibr_obj.ibr_obj_len = 1;
    }

  if ((status = __do_niscall (ibreq->ibr_name, NIS_IBREMOVE,
			      (xdrproc_t) xdr_ib_request,
			      (caddr_t) ibreq, (xdrproc_t) xdr_nis_result,
			      (caddr_t) res, 0, NULL)) != NIS_SUCCESS)
    res->status = status;

  nis_free_request (ibreq);

  return res;
}

nis_result *
nis_first_entry (const_nis_name name)
{
  nis_result *res;
  ib_request *ibreq = calloc (1, sizeof (ib_request));
  nis_error status;

  res = calloc (1, sizeof (nis_result));

  if (__create_ib_request (name, ibreq, 0) == NULL)
    {
      res->status = NIS_BADNAME;
      return res;
    }

  if ((status = __do_niscall (ibreq->ibr_name, NIS_IBFIRST,
			      (xdrproc_t) xdr_ib_request,
			      (caddr_t) ibreq, (xdrproc_t) xdr_nis_result,
			      (caddr_t) res, 0, NULL)) != NIS_SUCCESS)
    res->status = status;

  nis_free_request (ibreq);

  return res;
}

nis_result *
nis_next_entry (const_nis_name name, const netobj *cookie)
{
  nis_result *res;
  ib_request *ibreq = calloc (1, sizeof (ib_request));
  nis_error status;

  res = calloc (1, sizeof (nis_result));

  if (__create_ib_request (name, ibreq, 0) == NULL)
    {
      res->status = NIS_BADNAME;
      return res;
    }

  if (cookie != NULL)
    {
      ibreq->ibr_cookie.n_bytes = malloc (cookie->n_len);
      if (ibreq->ibr_cookie.n_bytes == NULL)
	{
	  res->status = NIS_NOMEMORY;
	  free (res);
	  return NULL;
	}
      memcpy (ibreq->ibr_cookie.n_bytes, cookie->n_bytes, cookie->n_len);
      ibreq->ibr_cookie.n_len = cookie->n_len;
    }

  if ((status = __do_niscall (ibreq->ibr_name, NIS_IBNEXT,
			      (xdrproc_t) xdr_ib_request,
			      (caddr_t) ibreq, (xdrproc_t) xdr_nis_result,
			      (caddr_t) res, 0, NULL)) != NIS_SUCCESS)
    res->status = status;

  nis_free_request (ibreq);

  return res;
}
