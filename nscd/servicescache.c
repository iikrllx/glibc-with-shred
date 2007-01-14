/* Cache handling for services lookup.
   Copyright (C) 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@drepper.com>, 2007.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/mman.h>

#include "nscd.h"
#include "dbg_log.h"


/* This is the standard reply in case the service is disabled.  */
static const serv_response_header disabled =
{
  .version = NSCD_VERSION,
  .found = -1,
  .s_name_len = 0,
  .s_proto_len = 0,
  .s_aliases_cnt = 0,
  .s_port = -1
};

/* This is the struct describing how to write this record.  */
const struct iovec serv_iov_disabled =
{
  .iov_base = (void *) &disabled,
  .iov_len = sizeof (disabled)
};


/* This is the standard reply in case we haven't found the dataset.  */
static const serv_response_header notfound =
{
  .version = NSCD_VERSION,
  .found = 0,
  .s_name_len = 0,
  .s_proto_len = 0,
  .s_aliases_cnt = 0,
  .s_port = -1
};


static void
cache_addserv (struct database_dyn *db, int fd, request_header *req,
	       const void *key, struct servent *serv, uid_t owner,
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
    serv_response_header resp;
    char strdata[0];
  } *dataset;

  assert (offsetof (struct dataset, resp) == offsetof (struct datahead, data));

  if (serv == NULL)
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
	  total = sizeof (notfound);

	  written = TEMP_FAILURE_RETRY (send (fd, &notfound, total,
					      MSG_NOSIGNAL));

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

	      /* If necessary, we also propagate the data to disk.  */
	      if (db->persistent)
		{
		  // XXX async OK?
		  uintptr_t pval = (uintptr_t) dataset & ~pagesize_m1;
		  msync ((void *) pval,
			 ((uintptr_t) dataset & pagesize_m1)
			 + sizeof (struct dataset) + req->key_len, MS_ASYNC);
		}

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
      size_t s_name_len = strlen (serv->s_name) + 1;
      size_t s_proto_len = strlen (serv->s_proto) + 1;
      uint32_t *s_aliases_len;
      size_t s_aliases_cnt;
      char *aliases;
      char *cp;
      size_t cnt;

      /* Determine the number of aliases.  */
      s_aliases_cnt = 0;
      for (cnt = 0; serv->s_aliases[cnt] != NULL; ++cnt)
	++s_aliases_cnt;
      /* Determine the length of all aliases.  */
      s_aliases_len = (uint32_t *) alloca (s_aliases_cnt * sizeof (uint32_t));
      total = 0;
      for (cnt = 0; cnt < s_aliases_cnt; ++cnt)
	{
	  s_aliases_len[cnt] = strlen (serv->s_aliases[cnt]) + 1;
	  total += s_aliases_len[cnt];
	}

      total += (sizeof (struct dataset)
		+ s_name_len
		+ s_proto_len
		+ s_aliases_cnt * sizeof (uint32_t));
      written = total;

      /* If we refill the cache, first assume the reconrd did not
	 change.  Allocate memory on the cache since it is likely
	 discarded anyway.  If it turns out to be necessary to have a
	 new record we can still allocate real memory.  */
      bool alloca_used = false;
      dataset = NULL;

      if (he == NULL)
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
      dataset->resp.s_name_len = s_name_len;
      dataset->resp.s_proto_len = s_proto_len;
      dataset->resp.s_port = serv->s_port;
      dataset->resp.s_aliases_cnt = s_aliases_cnt;

      cp = dataset->strdata;

      cp = mempcpy (cp, serv->s_name, s_name_len);
      cp = mempcpy (cp, serv->s_proto, s_proto_len);
      cp = mempcpy (cp, s_aliases_len, s_aliases_cnt * sizeof (uint32_t));

      /* Then the aliases.  */
      aliases = cp;
      for (cnt = 0; cnt < s_aliases_cnt; ++cnt)
	cp = mempcpy (cp, serv->s_aliases[cnt], s_aliases_len[cnt]);

      assert (cp
	      == dataset->strdata + total - offsetof (struct dataset,
						      strdata));

      char *key_copy = memcpy (cp, key, req->key_len);

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
	      /* The data has not changed.  We will just bump the
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

#ifdef HAVE_SENDFILE
	  if (__builtin_expect (db->mmap_used, 1) && !alloca_used)
	    {
	      assert (db->wr_fd != -1);
	      assert ((char *) &dataset->resp > (char *) db->data);
	      assert ((char *) &dataset->resp - (char *) db->head
		      + total
		      <= (sizeof (struct database_pers_head)
			  + db->head->module * sizeof (ref_t)
			  + db->head->data_size));
	      written = sendfileall (fd, db->wr_fd,
				     (char *) &dataset->resp
				     - (char *) db->head, total);
# ifndef __ASSUME_SENDFILE
	      if (written == -1 && errno == ENOSYS)
		goto use_write;
# endif
	    }
	  else
# ifndef __ASSUME_SENDFILE
	  use_write:
# endif
#endif
	    written = writeall (fd, &dataset->resp, total);
	}

      /* Add the record to the database.  But only if it has not been
	 stored on the stack.  */
      if (! alloca_used)
	{
	  /* If necessary, we also propagate the data to disk.  */
	  if (db->persistent)
	    {
	      // XXX async OK?
	      uintptr_t pval = (uintptr_t) dataset & ~pagesize_m1;
	      msync ((void *) pval,
		     ((uintptr_t) dataset & pagesize_m1)
		     + total + req->key_len, MS_ASYNC);
	    }

	  /* Now get the lock to safely insert the records.  */
	  pthread_rwlock_rdlock (&db->lock);

	  if (cache_add (req->type, key_copy, req->key_len,
			 &dataset->head, true, db, owner) < 0)
	    /* Could not allocate memory.  Make sure the
	       data gets discarded.  */
	    dataset->head.usable = false;

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
lookup (int type, char *key, struct servent *resultbufp, char *buffer,
	size_t buflen, struct servent **serv)
{
  char *proto = strrchr (key, '/');
  if (proto != NULL && proto != key)
    {
      key = strndupa (key, proto - key);
      if (proto[1] == '\0')
	proto = NULL;
      else
	++proto;
    }

  if (type == GETSERVBYNAME)
    return __getservbyname_r (key, proto, resultbufp, buffer, buflen, serv);

  assert (type == GETSERVBYPORT);
  return __getservbyport_r (atol (key), proto, resultbufp, buffer, buflen,
			    serv);
}


static void
addservbyX (struct database_dyn *db, int fd, request_header *req,
	    char *key, uid_t uid, struct hashentry *he, struct datahead *dh)
{
  /* Search for the entry matching the key.  Please note that we don't
     look again in the table whether the dataset is now available.  We
     simply insert it.  It does not matter if it is in there twice.  The
     pruning function only will look at the timestamp.  */
  size_t buflen = 1024;
  char *buffer = (char *) alloca (buflen);
  struct servent resultbuf;
  struct servent *serv;
  bool use_malloc = false;
  int errval = 0;

  if (__builtin_expect (debug_level > 0, 0))
    {
      if (he == NULL)
	dbg_log (_("Haven't found \"%s\" in services cache!"), key);
      else
	dbg_log (_("Reloading \"%s\" in services cache!"), key);
    }

  while (lookup (req->type, key, &resultbuf, buffer, buflen, &serv) != 0
	 && (errval = errno) == ERANGE)
    {
      errno = 0;

      if (__builtin_expect (buflen > 32768, 0))
	{
	  char *old_buffer = buffer;
	  buflen *= 2;
	  buffer = (char *) realloc (use_malloc ? buffer : NULL, buflen);
	  if (buffer == NULL)
	    {
	      /* We ran out of memory.  We cannot do anything but
		 sending a negative response.  In reality this should
		 never happen.  */
	      serv = NULL;
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
	buffer = (char *) extend_alloca (buffer, buflen, 2 * buflen);
    }

  cache_addserv (db, fd, req, key, serv, uid, he, dh, errval);

  if (use_malloc)
    free (buffer);
}


void
addservbyname (struct database_dyn *db, int fd, request_header *req,
	       void *key, uid_t uid)
{
  addservbyX (db, fd, req, key, uid, NULL, NULL);
}


void
readdservbyname (struct database_dyn *db, struct hashentry *he,
		 struct datahead *dh)
{
  request_header req =
    {
      .type = GETSERVBYNAME,
      .key_len = he->len
    };

  addservbyX (db, -1, &req, db->data + he->key, he->owner, he, dh);
}


void
addservbyport (struct database_dyn *db, int fd, request_header *req,
	       void *key, uid_t uid)
{
  addservbyX (db, fd, req, key, uid, NULL, NULL);
}


void
readdservbyport (struct database_dyn *db, struct hashentry *he,
		 struct datahead *dh)
{
  request_header req =
    {
      .type = GETSERVBYPORT,
      .key_len = he->len
    };

  addservbyX (db, -1, &req, db->data + he->key, he->owner, he, dh);
}
