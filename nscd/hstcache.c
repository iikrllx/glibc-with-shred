/* Cache handling for host lookup.
   Copyright (C) 1998-2002, 2003, 2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <libintl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/mman.h>
#include <stackinfo.h>

#include "nscd.h"
#include "dbg_log.h"


/* This is the standard reply in case the service is disabled.  */
static const hst_response_header disabled =
{
  .version = NSCD_VERSION,
  .found = -1,
  .h_name_len = 0,
  .h_aliases_cnt = 0,
  .h_addrtype = -1,
  .h_length = -1,
  .h_addr_list_cnt = 0,
  .error = NETDB_INTERNAL
};

/* This is the struct describing how to write this record.  */
const struct iovec hst_iov_disabled =
{
  .iov_base = (void *) &disabled,
  .iov_len = sizeof (disabled)
};


/* This is the standard reply in case we haven't found the dataset.  */
static const hst_response_header notfound =
{
  .version = NSCD_VERSION,
  .found = 0,
  .h_name_len = 0,
  .h_aliases_cnt = 0,
  .h_addrtype = -1,
  .h_length = -1,
  .h_addr_list_cnt = 0,
  .error = HOST_NOT_FOUND
};


static void
cache_addhst (struct database_dyn *db, int fd, request_header *req,
	      const void *key, struct hostent *hst, uid_t owner, int add_addr,
	      struct hashentry *he, struct datahead *dh, int errval)
{
  ssize_t total;
  ssize_t written;
  time_t t = time (NULL);

  /* We allocate all data in one memory block: the iov vector,
     the response header and the dataset itself.  */
  struct dataset
  {
    struct datahead head;
    hst_response_header resp;
    char strdata[0];
  } *dataset;

  assert (offsetof (struct dataset, resp) == offsetof (struct datahead, data));

  if (hst == NULL)
    {
      if (he != NULL && errval == EAGAIN)
	{
	  /* If we have an old record available but cannot find one
	     now because the service is not available we keep the old
	     record and make sure it does not get removed.  */
	  if (reload_count != UINT_MAX)
	    /* Do not reset the value if we never not reload the record.  */
	    dh->nreloads = reload_count - 1;

	  written = total = 0;
	}
      else
	{
	  /* We have no data.  This means we send the standard reply for this
	     case.  */
	  written = total = sizeof (notfound);

	  if (fd != -1)
	    written = TEMP_FAILURE_RETRY (write (fd, &notfound, total));

	  dataset = mempool_alloc (db, sizeof (struct dataset) + req->key_len);
	  /* If we cannot permanently store the result, so be it.  */
	  if (dataset != NULL)
	    {
	      dataset->head.allocsize = sizeof (struct dataset) + req->key_len;
	      dataset->head.recsize = total;
	      dataset->head.notfound = true;
	      dataset->head.nreloads = 0;
	      dataset->head.usable = true;

	      /* Compute the timeout time.  */
	      dataset->head.timeout = t + db->negtimeout;

	      /* This is the reply.  */
	      memcpy (&dataset->resp, &notfound, total);

	      /* Copy the key data.  */
	      memcpy (dataset->strdata, key, req->key_len);

	      /* Now get the lock to safely insert the records.  */
	      pthread_rwlock_rdlock (&db->lock);

	      if (cache_add (req->type, &dataset->strdata, req->key_len,
			     &dataset->head, true, db, owner) < 0)
		/* Ensure the data can be recovered.  */
		dataset->head.usable = false;

	      pthread_rwlock_unlock (&db->lock);

	      /* Mark the old entry as obsolete.  */
	      if (dh != NULL)
		dh->usable = false;
	    }
	  else
	    ++db->head->addfailed;
	}
    }
  else
    {
      /* Determine the I/O structure.  */
      size_t h_name_len = strlen (hst->h_name) + 1;
      size_t h_aliases_cnt;
      uint32_t *h_aliases_len;
      size_t h_addr_list_cnt;
      int addr_list_type;
      char *addresses;
      char *aliases;
      char *key_copy = NULL;
      char *cp;
      size_t cnt;

      /* Determine the number of aliases.  */
      h_aliases_cnt = 0;
      for (cnt = 0; hst->h_aliases[cnt] != NULL; ++cnt)
	++h_aliases_cnt;
      /* Determine the length of all aliases.  */
      h_aliases_len = (uint32_t *) alloca (h_aliases_cnt * sizeof (uint32_t));
      total = 0;
      for (cnt = 0; cnt < h_aliases_cnt; ++cnt)
	{
	  h_aliases_len[cnt] = strlen (hst->h_aliases[cnt]) + 1;
	  total += h_aliases_len[cnt];
	}

      /* Determine the number of addresses.  */
      h_addr_list_cnt = 0;
      for (cnt = 0; hst->h_addr_list[cnt]; ++cnt)
	++h_addr_list_cnt;

      if (h_addr_list_cnt == 0)
	/* Invalid entry.  */
	return;

      total += (sizeof (struct dataset)
		+ h_name_len
		+ h_aliases_cnt * sizeof (uint32_t)
		+ h_addr_list_cnt * hst->h_length);
      written = total;

      /* If we refill the cache, first assume the reconrd did not
	 change.  Allocate memory on the cache since it is likely
	 discarded anyway.  If it turns out to be necessary to have a
	 new record we can still allocate real memory.  */
      bool alloca_used = false;
      dataset = NULL;

      /* If the record contains more than one IP address (used for
	 load balancing etc) don't cache the entry.  This is something
	 the current cache handling cannot handle and it is more than
	 questionable whether it is worthwhile complicating the cache
	 handling just for handling such a special case. */
      if (he == NULL && (add_addr || hst->h_addr_list[1] == NULL))
	{
	  dataset = (struct dataset *) mempool_alloc (db,
						      total + req->key_len);
	  if (dataset == NULL)
	    ++db->head->addfailed;
	}

      if (dataset == NULL)
	{
	  /* We cannot permanently add the result in the moment.  But
	     we can provide the result as is.  Store the data in some
	     temporary memory.  */
	  dataset = (struct dataset *) alloca (total + req->key_len);

	  /* We cannot add this record to the permanent database.  */
	  alloca_used = true;
	}

      dataset->head.allocsize = total + req->key_len;
      dataset->head.recsize = total - offsetof (struct dataset, resp);
      dataset->head.notfound = false;
      dataset->head.nreloads = he == NULL ? 0 : (dh->nreloads + 1);
      dataset->head.usable = true;

      /* Compute the timeout time.  */
      dataset->head.timeout = t + db->postimeout;

      dataset->resp.version = NSCD_VERSION;
      dataset->resp.found = 1;
      dataset->resp.h_name_len = h_name_len;
      dataset->resp.h_aliases_cnt = h_aliases_cnt;
      dataset->resp.h_addrtype = hst->h_addrtype;
      dataset->resp.h_length = hst->h_length;
      dataset->resp.h_addr_list_cnt = h_addr_list_cnt;
      dataset->resp.error = NETDB_SUCCESS;

      cp = dataset->strdata;

      cp = mempcpy (cp, hst->h_name, h_name_len);
      cp = mempcpy (cp, h_aliases_len, h_aliases_cnt * sizeof (uint32_t));

      /* The normal addresses first.  */
      addresses = cp;
      for (cnt = 0; cnt < h_addr_list_cnt; ++cnt)
	cp = mempcpy (cp, hst->h_addr_list[cnt], hst->h_length);

      /* Then the aliases.  */
      aliases = cp;
      for (cnt = 0; cnt < h_aliases_cnt; ++cnt)
	cp = mempcpy (cp, hst->h_aliases[cnt], h_aliases_len[cnt]);

      assert (cp
	      == dataset->strdata + total - offsetof (struct dataset,
						      strdata));

      /* If we are adding a GETHOSTBYNAME{,v6} entry we must be prepared
	 that the answer we get from the NSS does not contain the key
	 itself.  This is the case if the resolver is used and the name
	 is extended by the domainnames from /etc/resolv.conf.  Therefore
	 we explicitly add the name here.  */
      if (req->type == GETHOSTBYNAME || req->type == GETHOSTBYNAMEv6)
	key_copy = memcpy (cp, key, req->key_len);
      else
	memset (cp, '\0', req->key_len);

      /* Now we can determine whether on refill we have to create a new
	 record or not.  */
      if (he != NULL)
	{
	  assert (fd == -1);

	  if (total + req->key_len == dh->allocsize
	      && total - offsetof (struct dataset, resp) == dh->recsize
	      && memcmp (&dataset->resp, dh->data,
			 dh->allocsize - offsetof (struct dataset, resp)) == 0)
	    {
	      /* The sata has not changed.  We will just bump the
		 timeout value.  Note that the new record has been
		 allocated on the stack and need not be freed.  */
	      dh->timeout = dataset->head.timeout;
	      ++dh->nreloads;
	    }
	  else
	    {
	      /* We have to create a new record.  Just allocate
		 appropriate memory and copy it.  */
	      struct dataset *newp
		= (struct dataset *) mempool_alloc (db, total + req->key_len);
	      if (newp != NULL)
		{
		  /* Adjust pointers into the memory block.  */
		  addresses = (char *) newp + (addresses - (char *) dataset);
		  aliases = (char *) newp + (aliases - (char *) dataset);
		  if (key_copy != NULL)
		    key_copy = (char *) newp + (key_copy - (char *) dataset);

		  dataset = memcpy (newp, dataset, total + req->key_len);
		  alloca_used = false;
		}

	      /* Mark the old record as obsolete.  */
	      dh->usable = false;
	    }
	}
      else
	{
	  /* We write the dataset before inserting it to the database
	     since while inserting this thread might block and so would
	     unnecessarily keep the receiver waiting.  */
	  assert (fd != -1);

	  written = TEMP_FAILURE_RETRY (write (fd, &dataset->resp, total));
	}

      /* Add the record to the database.  But only if it has not been
	 stored on the stack.

	 If the record contains more than one IP address (used for
	 load balancing etc) don't cache the entry.  This is something
	 the current cache handling cannot handle and it is more than
	 questionable whether it is worthwhile complicating the cache
	 handling just for handling such a special case. */
      if (! alloca_used)
	{
	  /* If necessary, we also propagate the data to disk.  */
	  if (db->persistent)
	    // XXX async OK?
	    msync (dataset, total + req->key_len, MS_ASYNC);

	  addr_list_type = (hst->h_length == NS_INADDRSZ
			    ? GETHOSTBYADDR : GETHOSTBYADDRv6);

	  /* Now get the lock to safely insert the records.  */
	  pthread_rwlock_rdlock (&db->lock);

	  /* NB: the following code is really complicated.  It has
	     seemlingly duplicated code paths which do the same.  The
	     problem is that we always must add the hash table entry
	     with the FIRST flag set first.  Otherwise we get dangling
	     pointers in case memory allocation fails.  */
	  assert (add_addr || hst->h_addr_list[1] == NULL);

	  /* Add the normal addresses.  */
	  if (add_addr)
	    {
	      for (cnt = 0; cnt < h_addr_list_cnt; ++cnt)
		{
		  if (cache_add (addr_list_type, addresses, hst->h_length,
				 &dataset->head, cnt == 0, db, owner) < 0)
		    {
		      /* Ensure the data can be recovered.  */
		      if (cnt == 0)
			dataset->head.usable = false;
		      goto out;
		    }
		  addresses += hst->h_length;
		}

	      /* If necessary the IPv6 addresses.  */
	      if (addr_list_type == GETHOSTBYADDR)
		for (cnt = 0; cnt < h_addr_list_cnt; ++cnt)
		  {
		    if (cache_add (GETHOSTBYADDRv6, addresses, IN6ADDRSZ,
				   &dataset->head, false, db, owner) < 0)
		      goto out;

		    addresses += IN6ADDRSZ;
		  }
	    }
	  /* Avoid adding names if more than one address is available.  See
	     above for more info.  */
	  else
	    {
	      assert (req->type == GETHOSTBYNAME
		      || req->type == GETHOSTBYNAMEv6
		      || req->type == GETHOSTBYADDR
		      || req->type == GETHOSTBYADDRv6);

	      /* If necessary add the key for this request.  */
	      if (req->type == GETHOSTBYNAME)
		{
		  bool first = true;
		  if (addr_list_type == GETHOSTBYADDR)
		    {
		      if (cache_add (GETHOSTBYNAME, key_copy, req->key_len,
				     &dataset->head, true, db, owner) < 0)
			{
			  /* Could not allocate memory.  Make sure the
			     data gets discarded.  */
			  dataset->head.usable = false;
			  goto out;
			}

		      first = false;
		    }
		  if (cache_add (GETHOSTBYNAMEv6, key_copy, req->key_len,
				 &dataset->head, first, db, owner) < 0)
		    {
		      /* Could not allocate memory.  Make sure the
			 data gets discarded.  */
		      if (first)
			dataset->head.usable = false;
		      goto out;
		    }
		}
	      else if (req->type == GETHOSTBYNAMEv6)
		{
		  if (cache_add (GETHOSTBYNAMEv6, key_copy, req->key_len,
				 &dataset->head, true, db, owner) < 0)
		    {
		      /* Could not allocate memory.  Make sure the
			 data gets discarded.  */
		      dataset->head.usable = false;
		      goto out;
		    }

		  if (addr_list_type == GETHOSTBYADDR
		      && cache_add (GETHOSTBYNAME, key_copy, req->key_len,
				    &dataset->head, false, db, owner) < 0)
		    goto out;
		}

	      /* And finally the name.  We mark this as the last entry.  */
	      if (addr_list_type == GETHOSTBYADDR
		  && req->type == GETHOSTBYADDR
		  && cache_add (GETHOSTBYNAME, dataset->strdata, h_name_len,
				&dataset->head, true, db, owner) < 0)
		{
		  /* Could not allocate memory.  Make sure the
		     data gets discarded.  */
		  dataset->head.usable = false;
		  goto out;
		}

	      if (cache_add (GETHOSTBYNAMEv6, dataset->strdata,
			     h_name_len, &dataset->head,
			     ((req->type == GETHOSTBYADDR
			       && addr_list_type != GETHOSTBYADDR)
			      || req->type == GETHOSTBYADDRv6), db,
			     owner) < 0)
		{
		  /* Could not allocate memory.  Make sure the
		     data gets discarded.  */
		  if ((req->type == GETHOSTBYADDR
		       && addr_list_type != GETHOSTBYADDR)
		      || req->type == GETHOSTBYADDRv6)
		    dataset->head.usable = false;
		  goto out;
		}

	      if (addr_list_type == GETHOSTBYADDR
		  && req->type != GETHOSTBYADDR
		  && cache_add (GETHOSTBYNAME, dataset->strdata, h_name_len,
				&dataset->head, false, db, owner) < 0)
		goto out;

	      /* First add all the aliases.  */
	      for (cnt = 0; cnt < h_aliases_cnt; ++cnt)
		{
		  if (addr_list_type == GETHOSTBYADDR)
		    if (cache_add (GETHOSTBYNAME, aliases,
				   h_aliases_len[cnt], &dataset->head,
				   false, db, owner) < 0)
		      break;

		  if (cache_add (GETHOSTBYNAMEv6, aliases,
				 h_aliases_len[cnt], &dataset->head,
				 false, db, owner) < 0)
		    break;

		  aliases += h_aliases_len[cnt];
		}
	    }

	out:
	  pthread_rwlock_unlock (&db->lock);
	}
    }

  if (__builtin_expect (written != total, 0) && debug_level > 0)
    {
      char buf[256];
      dbg_log (_("short write in %s: %s"),  __FUNCTION__,
	       strerror_r (errno, buf, sizeof (buf)));
    }
}


static int
lookup (int type, void *key, struct hostent *resultbufp, char *buffer,
	size_t buflen, struct hostent **hst)
{
  if (type == GETHOSTBYNAME)
    return __gethostbyname2_r (key, AF_INET, resultbufp, buffer, buflen, hst,
			       &h_errno);
  else if (type == GETHOSTBYNAMEv6)
    return __gethostbyname2_r (key, AF_INET6, resultbufp, buffer, buflen, hst,
			       &h_errno);
  else if (type == GETHOSTBYADDR)
    return __gethostbyaddr_r (key, NS_INADDRSZ, AF_INET, resultbufp, buffer,
			      buflen, hst, &h_errno);
  else
    return __gethostbyaddr_r (key, NS_IN6ADDRSZ, AF_INET6, resultbufp, buffer,
			      buflen, hst, &h_errno);
}


static void
addhstbyX (struct database_dyn *db, int fd, request_header *req,
	   void *key, uid_t uid, struct hashentry *he, struct datahead *dh)
{
  /* Search for the entry matching the key.  Please note that we don't
     look again in the table whether the dataset is now available.  We
     simply insert it.  It does not matter if it is in there twice.  The
     pruning function only will look at the timestamp.  */
  int buflen = 1024;
  char *buffer = (char *) alloca (buflen);
  struct hostent resultbuf;
  struct hostent *hst;
  uid_t oldeuid = 0;
  bool use_malloc = false;
  int errval = 0;

  if (__builtin_expect (debug_level > 0, 0))
    {
      if (he == NULL)
	dbg_log (_("Haven't found \"%s\" in hosts cache!"), (char *) key);
      else
	dbg_log (_("Reloading \"%s\" in hosts cache!"), (char *) key);
    }

  if (db->secure)
    {
      oldeuid = geteuid ();
      seteuid (uid);
    }

  while (lookup (req->type, key, &resultbuf, buffer, buflen, &hst) != 0
	 && h_errno == NETDB_INTERNAL
	 && (errval = errno) == ERANGE)
    {
      char *old_buffer = buffer;
      errno = 0;
#define INCR 1024

      if (__builtin_expect (buflen > 32768, 0))
	{
	  buflen += INCR;
	  buffer = (char *) realloc (use_malloc ? buffer : NULL, buflen);
	  if (buffer == NULL)
	    {
	      /* We ran out of memory.  We cannot do anything but
		 sending a negative response.  In reality this should
		 never happen.  */
	      hst = NULL;
	      buffer = old_buffer;

	      /* We set the error to indicate this is (possibly) a
		 temporary error and that it does not mean the entry
		 is not available at all.  */
	      errval = EAGAIN;
	      break;
	    }
	  use_malloc = true;
	}
      else
	/* Allocate a new buffer on the stack.  If possible combine it
	   with the previously allocated buffer.  */
	buffer = (char *) extend_alloca (buffer, buflen, buflen + INCR);
    }

  if (db->secure)
    seteuid (oldeuid);

  cache_addhst (db, fd, req, key, hst, uid, 0, he, dh,
		h_errno == TRY_AGAIN ? errval : 0);

  if (use_malloc)
    free (buffer);
}


void
addhstbyname (struct database_dyn *db, int fd, request_header *req,
	      void *key, uid_t uid)
{
  addhstbyX (db, fd, req, key, uid, NULL, NULL);
}


void
readdhstbyname (struct database_dyn *db, struct hashentry *he,
		struct datahead *dh)
{
  request_header req =
    {
      .type = GETHOSTBYNAME,
      .key_len = he->len
    };

  addhstbyX (db, -1, &req, db->data + he->key, he->owner, he, dh);
}


void
addhstbyaddr (struct database_dyn *db, int fd, request_header *req,
	      void *key, uid_t uid)
{
  addhstbyX (db, fd, req, key, uid, NULL, NULL);
}


void
readdhstbyaddr (struct database_dyn *db, struct hashentry *he,
		struct datahead *dh)
{
  request_header req =
    {
      .type = GETHOSTBYADDR,
      .key_len = he->len
    };

  addhstbyX (db, -1, &req, db->data + he->key, he->owner, he, dh);
}


void
addhstbynamev6 (struct database_dyn *db, int fd, request_header *req,
		void *key, uid_t uid)
{
  addhstbyX (db, fd, req, key, uid, NULL, NULL);
}


void
readdhstbynamev6 (struct database_dyn *db, struct hashentry *he,
		  struct datahead *dh)
{
  request_header req =
    {
      .type = GETHOSTBYNAMEv6,
      .key_len = he->len
    };

  addhstbyX (db, -1, &req, db->data + he->key, he->owner, he, dh);
}


void
addhstbyaddrv6 (struct database_dyn *db, int fd, request_header *req,
		void *key, uid_t uid)
{
  addhstbyX (db, fd, req, key, uid, NULL, NULL);
}


void
readdhstbyaddrv6 (struct database_dyn *db, struct hashentry *he,
		  struct datahead *dh)
{
  request_header req =
    {
      .type = GETHOSTBYADDRv6,
      .key_len = he->len
    };

  addhstbyX (db, -1, &req, db->data + he->key, he->owner, he, dh);
}
