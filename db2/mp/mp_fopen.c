/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1996, 1997
 *	Sleepycat Software.  All rights reserved.
 */
#include "config.h"

#ifndef lint
static const char sccsid[] = "@(#)mp_fopen.c	10.32 (Sleepycat) 11/26/97";
#endif /* not lint */

#ifndef NO_SYSTEM_INCLUDES
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif

#include "db_int.h"
#include "shqueue.h"
#include "db_shash.h"
#include "mp.h"
#include "common_ext.h"

static int __memp_mf_close __P((DB_MPOOL *, DB_MPOOLFILE *));
static int __memp_mf_open __P((DB_MPOOL *, DB_MPOOLFILE *,
    const char *, int, size_t, off_t, int, DBT *, u_int8_t *, MPOOLFILE **));

/*
 * memp_fopen --
 *	Open a backing file for the memory pool.
 */
int
memp_fopen(dbmp, path, ftype,
    flags, mode, pagesize, lsn_offset, pgcookie, fileid, retp)
	DB_MPOOL *dbmp;
	const char *path;
	int ftype, flags, mode, lsn_offset;
	size_t pagesize;
	DBT *pgcookie;
	u_int8_t *fileid;
	DB_MPOOLFILE **retp;
{
	int ret;

	/* Validate arguments. */
	if ((ret = __db_fchk(dbmp->dbenv,
	    "memp_fopen", flags, DB_CREATE | DB_NOMMAP | DB_RDONLY)) != 0)
		return (ret);

	/* Require a non-zero pagesize. */
	if (pagesize == 0) {
		__db_err(dbmp->dbenv, "memp_fopen: pagesize not specified");
		return (EINVAL);
	}

	return (__memp_fopen(dbmp, NULL, path, ftype,
	    flags, mode, pagesize, lsn_offset, pgcookie, fileid, 1, retp));
}

/*
 * __memp_fopen --
 *	Open a backing file for the memory pool; internal version.
 *
 * PUBLIC: int __memp_fopen __P((DB_MPOOL *, MPOOLFILE *, const char *, int,
 * PUBLIC:    int, int, size_t, int, DBT *, u_int8_t *, int, DB_MPOOLFILE **));
 */
int
__memp_fopen(dbmp, mfp, path,
    ftype, flags, mode, pagesize, lsn_offset, pgcookie, fileid, needlock, retp)
	DB_MPOOL *dbmp;
	MPOOLFILE *mfp;
	const char *path;
	int ftype, flags, mode, lsn_offset, needlock;
	size_t pagesize;
	DBT *pgcookie;
	u_int8_t *fileid;
	DB_MPOOLFILE **retp;
{
	DB_ENV *dbenv;
	DB_MPOOLFILE *dbmfp;
	off_t size;
	int ret;
	u_int8_t idbuf[DB_FILE_ID_LEN];
	char *rpath;

	/*
	 * XXX
	 * If mfp is provided, the following arguments do NOT need to be
	 * specified:
	 *      lsn_offset
	 *      pgcookie
	 *      fileid
	 */
	dbenv = dbmp->dbenv;
	ret = 0;
	rpath = NULL;

	/* Allocate and initialize the per-process structure. */
	if ((dbmfp =
	    (DB_MPOOLFILE *)__db_calloc(1, sizeof(DB_MPOOLFILE))) == NULL) {
		__db_err(dbenv, "memp_fopen: %s", strerror(ENOMEM));
		return (ENOMEM);
	}
	dbmfp->dbmp = dbmp;
	dbmfp->fd = -1;
	if (LF_ISSET(DB_RDONLY))
		F_SET(dbmfp, MP_READONLY);

	if (path == NULL) {
		if (LF_ISSET(DB_RDONLY)) {
			__db_err(dbenv,
			    "memp_fopen: temporary files can't be readonly");
			ret = EINVAL;
			goto err;
		}
		size = 0;
	} else {
		/* Get the real name for this file and open it. */
		if ((ret = __db_appname(dbenv,
		    DB_APP_DATA, NULL, path, NULL, &rpath)) != 0)
			goto err;
		if ((ret = __db_open(rpath,
		    LF_ISSET(DB_CREATE | DB_RDONLY), DB_CREATE | DB_RDONLY,
		    mode, &dbmfp->fd)) != 0) {
			__db_err(dbenv, "%s: %s", rpath, strerror(ret));
			goto err;
		}

		/* Don't permit files that aren't a multiple of the pagesize. */
		if ((ret = __db_ioinfo(rpath, dbmfp->fd, &size, NULL)) != 0) {
			__db_err(dbenv, "%s: %s", rpath, strerror(ret));
			goto err;
		}
		if (size % pagesize) {
			__db_err(dbenv,
			    "%s: file size not a multiple of the pagesize",
			    rpath);
			ret = EINVAL;
			goto err;
		}

		/*
		 * Get the file id if we weren't given one.  Generated file id's
		 * don't use timestamps, otherwise there'd be no chance of any
		 * other process joining the party.
		 */
		if (mfp == NULL && fileid == NULL) {
			if ((ret = __db_fileid(dbenv, rpath, 0, idbuf)) != 0)
				goto err;
			fileid = idbuf;
		}
	}

	/*
	 * If we weren't provided an underlying shared object to join with,
	 * find/allocate the shared file objects.  Also allocate space for
	 * for the per-process thread lock.
	 */
	if (needlock)
		LOCKREGION(dbmp);

	if (mfp == NULL)
		ret = __memp_mf_open(dbmp, dbmfp, path,
		    ftype, pagesize, size, lsn_offset, pgcookie, fileid, &mfp);
	else {
		++mfp->ref;
		ret = 0;
	}
	if (ret == 0 &&
	    F_ISSET(dbmp, MP_LOCKHANDLE) && (ret =
	    __memp_ralloc(dbmp, sizeof(db_mutex_t), NULL, &dbmfp->mutexp)) == 0)
		LOCKINIT(dbmp, dbmfp->mutexp);

	if (needlock)
		UNLOCKREGION(dbmp);
	if (ret != 0)
		goto err;

	dbmfp->mfp = mfp;

	/*
	 * If a file:
	 *	+ is read-only
	 *	+ isn't temporary
	 *	+ doesn't require any pgin/pgout support
	 *	+ the DB_NOMMAP flag wasn't set
	 *	+ and is less than mp_mmapsize bytes in size
	 *
	 * we can mmap it instead of reading/writing buffers.  Don't do error
	 * checking based on the mmap call failure.  We want to do normal I/O
	 * on the file if the reason we failed was because the file was on an
	 * NFS mounted partition, and we can fail in buffer I/O just as easily
	 * as here.
	 *
	 * XXX
	 * We'd like to test to see if the file is too big to mmap.  Since we
	 * don't know what size or type off_t's or size_t's are, or the largest
	 * unsigned integral type is, or what random insanity the local C
	 * compiler will perpetrate, doing the comparison in a portable way is
	 * flatly impossible.  Hope that mmap fails if the file is too large.
	 */
#define	DB_MAXMMAPSIZE	(10 * 1024 * 1024)	/* 10 Mb. */
	if (F_ISSET(mfp, MP_CAN_MMAP)) {
		if (!F_ISSET(dbmfp, MP_READONLY))
			F_CLR(mfp, MP_CAN_MMAP);
		if (path == NULL)
			F_CLR(mfp, MP_CAN_MMAP);
		if (ftype != 0)
			F_CLR(mfp, MP_CAN_MMAP);
		if (LF_ISSET(DB_NOMMAP))
			F_CLR(mfp, MP_CAN_MMAP);
		if (size > (dbenv == NULL || dbenv->mp_mmapsize == 0 ?
		    DB_MAXMMAPSIZE : (off_t)dbenv->mp_mmapsize))
			F_CLR(mfp, MP_CAN_MMAP);
	}
	dbmfp->addr = NULL;
	if (F_ISSET(mfp, MP_CAN_MMAP)) {
		dbmfp->len = size;
		if (__db_map(dbmfp->fd, dbmfp->len, 1, 1, &dbmfp->addr) != 0) {
			dbmfp->addr = NULL;
			F_CLR(mfp, MP_CAN_MMAP);
		}
	}

	LOCKHANDLE(dbmp, dbmp->mutexp);
	TAILQ_INSERT_TAIL(&dbmp->dbmfq, dbmfp, q);
	UNLOCKHANDLE(dbmp, dbmp->mutexp);

	*retp = dbmfp;
	return (0);

err:	/*
	 * Note that we do not have to free the thread mutex, because we
	 * never get to here after we have successfully allocated it.
	 */
	if (rpath != NULL)
		FREES(rpath);
	if (dbmfp->fd != -1)
		(void)__db_close(dbmfp->fd);
	if (dbmfp != NULL)
		FREE(dbmfp, sizeof(DB_MPOOLFILE));
	return (ret);
}

/*
 * __memp_mf_open --
 *	Open an MPOOLFILE.
 */
static int
__memp_mf_open(dbmp, dbmfp, path,
    ftype, pagesize, size, lsn_offset, pgcookie, fileid, retp)
	DB_MPOOL *dbmp;
	DB_MPOOLFILE *dbmfp;
	const char *path;
	int ftype, lsn_offset;
	size_t pagesize;
	off_t size;
	DBT *pgcookie;
	u_int8_t *fileid;
	MPOOLFILE **retp;
{
	MPOOLFILE *mfp;
	int ret;
	void *p;

#define	ISTEMPORARY	(path == NULL)

	/*
	 * Walk the list of MPOOLFILE's, looking for a matching file.
	 * Temporary files can't match previous files.
	 */
	if (!ISTEMPORARY)
		for (mfp = SH_TAILQ_FIRST(&dbmp->mp->mpfq, __mpoolfile);
		    mfp != NULL; mfp = SH_TAILQ_NEXT(mfp, q, __mpoolfile)) {
			if (F_ISSET(mfp, MP_TEMP))
				continue;
			if (!memcmp(fileid,
			    R_ADDR(dbmp, mfp->fileid_off), DB_FILE_ID_LEN)) {
				if (ftype != mfp->ftype ||
				    pagesize != mfp->stat.st_pagesize) {
					__db_err(dbmp->dbenv,
					    "%s: ftype or pagesize changed",
					    path);
					return (EINVAL);
				}

				/* Found it: increment the reference count. */
				++mfp->ref;
				*retp = mfp;
				return (0);
			}
		}

	/* Allocate a new MPOOLFILE. */
	if ((ret = __memp_ralloc(dbmp, sizeof(MPOOLFILE), NULL, &mfp)) != 0)
		return (ret);
	*retp = mfp;

	/* Initialize the structure. */
	memset(mfp, 0, sizeof(MPOOLFILE));
	mfp->ref = 1;
	mfp->ftype = ftype;
	mfp->lsn_off = lsn_offset;

	/*
	 * If the user specifies DB_MPOOL_LAST or DB_MPOOL_NEW on a memp_fget,
	 * we have to know the last page in the file.  Figure it out and save
	 * it away.
	 */
	mfp->stat.st_pagesize = pagesize;
	mfp->last_pgno = size == 0 ? 0 : (size - 1) / mfp->stat.st_pagesize;

	F_SET(mfp, MP_CAN_MMAP);
	if (ISTEMPORARY)
		F_SET(mfp, MP_TEMP);
	else {
		/* Copy the file path into shared memory. */
		if ((ret = __memp_ralloc(dbmp,
		    strlen(path) + 1, &mfp->path_off, &p)) != 0)
			goto err;
		memcpy(p, path, strlen(path) + 1);

		/* Copy the file identification string into shared memory. */
		if ((ret = __memp_ralloc(dbmp,
		    DB_FILE_ID_LEN, &mfp->fileid_off, &p)) != 0)
			goto err;
		memcpy(p, fileid, DB_FILE_ID_LEN);
	}

	/* Copy the page cookie into shared memory. */
	if (pgcookie == NULL || pgcookie->size == 0) {
		mfp->pgcookie_len = 0;
		mfp->pgcookie_off = 0;
	} else {
		if ((ret = __memp_ralloc(dbmp,
		    pgcookie->size, &mfp->pgcookie_off, &p)) != 0)
			goto err;
		memcpy(p, pgcookie->data, pgcookie->size);
		mfp->pgcookie_len = pgcookie->size;
	}

	/* Prepend the MPOOLFILE to the list of MPOOLFILE's. */
	SH_TAILQ_INSERT_HEAD(&dbmp->mp->mpfq, mfp, q, __mpoolfile);

	if (0) {
err:		if (mfp->path_off != 0)
			__db_shalloc_free(dbmp->addr,
			    R_ADDR(dbmp, mfp->path_off));
		if (mfp->fileid_off != 0)
			__db_shalloc_free(dbmp->addr,
			    R_ADDR(dbmp, mfp->fileid_off));
		if (mfp != NULL)
			__db_shalloc_free(dbmp->addr, mfp);
		mfp = NULL;
	}
	return (0);
}

/*
 * memp_fclose --
 *	Close a backing file for the memory pool.
 */
int
memp_fclose(dbmfp)
	DB_MPOOLFILE *dbmfp;
{
	DB_MPOOL *dbmp;
	int ret, t_ret;

	dbmp = dbmfp->dbmp;
	ret = 0;

	/* Complain if pinned blocks never returned. */
	if (dbmfp->pinref != 0)
		__db_err(dbmp->dbenv, "%s: close: %lu blocks left pinned",
		    __memp_fn(dbmfp), (u_long)dbmfp->pinref);

	/* Remove the DB_MPOOLFILE structure from the list. */
	LOCKHANDLE(dbmp, dbmp->mutexp);
	TAILQ_REMOVE(&dbmp->dbmfq, dbmfp, q);
	UNLOCKHANDLE(dbmp, dbmp->mutexp);

	/* Close the underlying MPOOLFILE. */
	(void)__memp_mf_close(dbmp, dbmfp);

	/* Discard any mmap information. */
	if (dbmfp->addr != NULL &&
	    (ret = __db_unmap(dbmfp->addr, dbmfp->len)) != 0)
		__db_err(dbmp->dbenv,
		    "%s: %s", __memp_fn(dbmfp), strerror(ret));

	/* Close the file; temporary files may not yet have been created. */
	if (dbmfp->fd != -1 && (t_ret = __db_close(dbmfp->fd)) != 0) {
		__db_err(dbmp->dbenv,
		    "%s: %s", __memp_fn(dbmfp), strerror(t_ret));
		if (ret != 0)
			t_ret = ret;
	}

	/* Free memory. */
	if (dbmfp->mutexp != NULL) {
		LOCKREGION(dbmp);
		__db_shalloc_free(dbmp->addr, dbmfp->mutexp);
		UNLOCKREGION(dbmp);
	}

	/* Discard the DB_MPOOLFILE structure. */
	FREE(dbmfp, sizeof(DB_MPOOLFILE));

	return (ret);
}

/*
 * __memp_mf_close --
 *	Close down an MPOOLFILE.
 */
static int
__memp_mf_close(dbmp, dbmfp)
	DB_MPOOL *dbmp;
	DB_MPOOLFILE *dbmfp;
{
	BH *bhp, *nbhp;
	MPOOL *mp;
	MPOOLFILE *mfp;
	size_t mf_offset;

	mp = dbmp->mp;
	mfp = dbmfp->mfp;

	LOCKREGION(dbmp);

	/* If more than a single reference, simply decrement. */
	if (mfp->ref > 1) {
		--mfp->ref;
		goto ret1;
	}

	/*
	 * Move any BH's held by the file to the free list.  We don't free the
	 * memory itself because we may be discarding the memory pool, and it's
	 * fairly expensive to reintegrate the buffers back into the region for
	 * no purpose.
	 */
	mf_offset = R_OFFSET(dbmp, mfp);
	for (bhp = SH_TAILQ_FIRST(&mp->bhq, __bh); bhp != NULL; bhp = nbhp) {
		nbhp = SH_TAILQ_NEXT(bhp, q, __bh);

#ifdef DEBUG_NO_DIRTY
		/* Complain if we find any blocks that were left dirty. */
		if (F_ISSET(bhp, BH_DIRTY))
			__db_err(dbmp->dbenv,
			    "%s: close: pgno %lu left dirty; ref %lu",
			    __memp_fn(dbmfp),
			    (u_long)bhp->pgno, (u_long)bhp->ref);
#endif

		if (bhp->mf_offset == mf_offset) {
			if (F_ISSET(bhp, BH_DIRTY)) {
				++mp->stat.st_page_clean;
				--mp->stat.st_page_dirty;
			}
			__memp_bhfree(dbmp, mfp, bhp, 0);
			SH_TAILQ_INSERT_HEAD(&mp->bhfq, bhp, q, __bh);
		}
	}

	/* Delete from the list of MPOOLFILEs. */
	SH_TAILQ_REMOVE(&mp->mpfq, mfp, q, __mpoolfile);

	/* Free the space. */
	__db_shalloc_free(dbmp->addr, mfp);
	if (mfp->path_off != 0)
		__db_shalloc_free(dbmp->addr, R_ADDR(dbmp, mfp->path_off));
	if (mfp->fileid_off != 0)
		__db_shalloc_free(dbmp->addr, R_ADDR(dbmp, mfp->fileid_off));
	if (mfp->pgcookie_off != 0)
		__db_shalloc_free(dbmp->addr, R_ADDR(dbmp, mfp->pgcookie_off));

ret1:	UNLOCKREGION(dbmp);
	return (0);
}
