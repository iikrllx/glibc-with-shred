/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1996, 1997
 *	Sleepycat Software.  All rights reserved.
 */
#include "config.h"

#ifndef lint
static const char sccsid[] = "@(#)log_put.c	10.14 (Sleepycat) 9/23/97";
#endif /* not lint */

#ifndef NO_SYSTEM_INCLUDES
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#endif

#include "db_int.h"
#include "shqueue.h"
#include "db_page.h"
#include "log.h"
#include "hash.h"
#include "common_ext.h"

static int __log_fill __P((DB_LOG *, void *, u_int32_t));
static int __log_newfd __P((DB_LOG *));
static int __log_write __P((DB_LOG *, void *, u_int32_t));
static int __log_putr __P((DB_LOG *, const DBT *, u_int32_t));

/*
 * log_put --
 *	Write a log record.
 */
int
log_put(dblp, lsn, dbt, flags)
	DB_LOG *dblp;
	DB_LSN *lsn;
	const DBT *dbt;
	int flags;
{
	int ret;

	/* Validate arguments. */
#define	OKFLAGS	(DB_CHECKPOINT | DB_FLUSH)
	if (flags != 0) {
		if ((ret =
		    __db_fchk(dblp->dbenv, "log_put", flags, OKFLAGS)) != 0)
			return (ret);
		switch (flags) {
		case DB_CHECKPOINT:
		case DB_FLUSH:
		case 0:
			break;
		default:
			return (__db_ferr(dblp->dbenv, "log_put", 1));
		}
	}

	LOCK_LOGREGION(dblp);

	ret = __log_put(dblp, lsn, dbt, flags);

	UNLOCK_LOGREGION(dblp);

	return (ret);
}

/*
 * __log_put --
 *	Write a log record; internal version.
 *
 * PUBLIC: int __log_put __P((DB_LOG *, DB_LSN *, const DBT *, int));
 */
int
__log_put(dblp, lsn, dbt, flags)
	DB_LOG *dblp;
	DB_LSN *lsn;
	const DBT *dbt;
	int flags;
{
	DBT t;
	DBT fid_dbt;
	DB_LSN r_unused;
	FNAME *fnp;
	LOG *lp;
	u_int32_t lastoff;
	int ret;

	lp = dblp->lp;

	/* If this information won't fit in the file, swap files. */
	if (lp->lsn.offset + sizeof(HDR) + dbt->size > lp->persist.lg_max) {
		if (sizeof(HDR) +
		    sizeof(LOGP) + dbt->size > lp->persist.lg_max) {
			__db_err(dblp->dbenv,
			    "log_put: record larger than maximum file size");
			return (EINVAL);
		}
		if (lp->b_off != 0) {
			if ((ret = __log_write(dblp, lp->buf, lp->b_off)) != 0)
				return (ret);
			if ((ret = __db_fsync(dblp->lfd)) != 0)
				return (ret);
			lp->s_lsn.file = lp->lsn.file;
			lp->s_lsn.offset = lp->lsn.offset - 1;
		}

		/*
		 * Save the last known offset from the previous file, we'll
		 * need it to initialize the persistent header information.
		 */
		lastoff = lp->lsn.offset;

		++lp->lsn.file;
		lp->lsn.offset = 0;
		lp->w_off = 0;
	} else
		lastoff = 0;

	/*
	 * Insert persistent information as the first record in every file.
	 * Note that the previous length is wrong for the very first record
	 * of the log, but that's okay, we check for it during retrieval.
	 */
	if (lp->lsn.offset == 0) {
		t.data = &lp->persist;
		t.size = sizeof(LOGP);
		if ((ret = __log_putr(dblp,
		    &t, lastoff == 0 ? 0 : lastoff - lp->len)) != 0)
			return (ret);
	}

	/* Initialize the LSN information returned to the user. */
	lsn->file = lp->lsn.file;
	lsn->offset = lp->lsn.offset;

	/* Put out the user's record. */
	if ((ret = __log_putr(dblp, dbt, lp->lsn.offset - lp->len)) != 0)
		return (ret);

	/*
	 * On a checkpoint, we:
	 *	Put out the checkpoint record (above).
	 *	Save the LSN of the checkpoint in the shared region.
	 *	Append the set of file name information into the log.
	 *	Flush the current buffer contents to disk.
	 *	Sync the log to disk.
	 *	Save the time the checkpoint was written.
	 *	Reset the bytes written since the last checkpoint.
	 */
	if (flags == DB_CHECKPOINT) {
		lp->c_lsn = *lsn;

		for (fnp = SH_TAILQ_FIRST(&dblp->lp->fq, __fname);
		    fnp != NULL; fnp = SH_TAILQ_NEXT(fnp, q, __fname)) {
			t.data = ADDR(dblp, fnp->name_off);
			t.size = strlen(t.data) + 1;
			memset(&fid_dbt, 0, sizeof(fid_dbt));
			fid_dbt.data = ADDR(dblp, fnp->fileid_off);
			fid_dbt.size = DB_FILE_ID_LEN;
			if ((ret = __log_register_log(dblp, NULL, &r_unused,
			    0, &t, &fid_dbt, fnp->id, fnp->s_type)) != 0)
				return (ret);
		}
		if (lp->b_off != 0 &&
		    (ret = __log_write(dblp, lp->buf, lp->b_off)) != 0)
			return (ret);
		(void)time(&lp->chkpt);
		lp->written = 0;

		if ((ret = __db_fsync(dblp->lfd)) != 0)
			return (ret);
		lp->s_lsn.file = lp->lsn.file;
		lp->s_lsn.offset = lp->lsn.offset - 1;
	}

	/* We always flush on a checkpoint. */
	if (flags == DB_FLUSH || flags == DB_CHECKPOINT) {
		if (lp->b_off != 0 &&
		    (ret = __log_write(dblp, lp->buf, lp->b_off)) != 0)
			return (ret);

		if ((ret = __db_fsync(dblp->lfd)) != 0)
			return (ret);
		lp->s_lsn.file = lp->lsn.file;
		lp->s_lsn.offset = lp->lsn.offset - 1;
	}

	/*
	 * If we just did I/O, i.e., this LSN could have spanned the start of
	 * the in-core buffer, we remember it so that we can flush correctly
	 * during a sync.
	 */
	if (lsn->offset < lp->w_off && lsn->offset + lp->len > lp->w_off)
		lp->span_lsn = *lsn;
	return (0);
}

/*
 * __log_putr --
 *	Actually put a record into the log.
 */
static int
__log_putr(dblp, dbt, prev)
	DB_LOG *dblp;
	const DBT *dbt;
	u_int32_t prev;
{
	HDR hdr;
	LOG *lp;
	int ret;

	lp = dblp->lp;

	/*
	 * Initialize the header.  If we just switched files, lsn.offset will
	 * be 0, and what we really want is the offset of the previous record
	 * in the previous file.  Fortunately, prev holds the value we want.
	 */
	hdr.prev = prev;
	hdr.len = sizeof(HDR) + dbt->size;
	hdr.cksum = __ham_func4(dbt->data, dbt->size);

	if ((ret = __log_fill(dblp, &hdr, sizeof(HDR))) != 0)
		return (ret);
	lp->lsn.offset += sizeof(HDR);

	if ((ret = __log_fill(dblp, dbt->data, dbt->size)) != 0)
		return (ret);
	lp->lsn.offset += dbt->size;

	lp->len = sizeof(HDR) + dbt->size;
	return (0);
}

/*
 * log_flush --
 *	Write all records less than or equal to the specified LSN.
 */
int
log_flush(dblp, lsn)
	DB_LOG *dblp;
	const DB_LSN *lsn;
{
	DB_LSN t_lsn;
	LOG *lp;
	int ret;

	ret = 0;
	lp = dblp->lp;

	LOCK_LOGREGION(dblp);

	/* If no LSN specified, flush the entire log. */
	if (lsn == NULL) {
		t_lsn.file = lp->lsn.file;
		t_lsn.offset = lp->lsn.offset - lp->len;
		lsn = &t_lsn;
	}

	/* If it's a non-existent record, it's an error. */
	if (lsn->file > lp->lsn.file ||
	    (lsn->file == lp->lsn.file && lsn->offset > lp->lsn.offset)) {
		__db_err(dblp->dbenv, "log_flush: LSN past current end-of-log");
		ret = EINVAL;
		goto ret1;
	}

	/*
	 * If it's from a previous file, we're done because we sync each
	 * file when we move to a new one.
	 */
	if (lsn->file < lp->lsn.file)
		goto ret1;

	/*
	 * If it's less than the last-sync'd offset, we've already sync'd
	 * this LSN.
	 */
	if (lsn->offset <= lp->s_lsn.offset)
		goto ret1;

	/*
	 * We may need to write the current buffer.  We have to write the
	 * current buffer if the sync LSN is greater than or equal to the
	 * saved spanning-LSN.
	 */
	if (lsn->file >= lp->span_lsn.file &&
	    lsn->offset >= lp->span_lsn.offset)
		if ((ret = __log_write(dblp, lp->buf, lp->b_off)) != 0)
			goto ret1;

	/* Acquire a file descriptor if we don't have one. */
	if (dblp->lfname != dblp->lp->lsn.file &&
	    (ret = __log_newfd(dblp)) != 0)
		goto ret1;

	if ((ret = __db_fsync(dblp->lfd)) != 0)
		goto ret1;

	lp->s_lsn.file = lp->lsn.file;
	lp->s_lsn.offset = lsn->offset;

ret1:	UNLOCK_LOGREGION(dblp);
	return (ret);
}

/*
 * __log_fill --
 *	Write information into the log.
 */
static int
__log_fill(dblp, addr, len)
	DB_LOG *dblp;
	void *addr;
	u_int32_t len;
{
	LOG *lp;
	u_int32_t nrec;
	size_t nw, remain;
	int ret;

	/* Copy out the data. */
	for (lp = dblp->lp; len > 0;) {
		/*
		 * If we're on a buffer boundary and the data is big enough,
		 * copy as many records as we can directly from the data.
		 */
		if (lp->b_off == 0 && len >= sizeof(lp->buf)) {
			nrec = len / sizeof(lp->buf);
			if ((ret = __log_write(dblp,
			    addr, nrec * sizeof(lp->buf))) != 0)
				return (ret);
			addr = (u_int8_t *)addr + nrec * sizeof(lp->buf);
			len -= nrec * sizeof(lp->buf);
			continue;
		}

		/* Figure out how many bytes we can copy this time. */
		remain = sizeof(lp->buf) - lp->b_off;
		nw = remain > len ? len : remain;
		memcpy(lp->buf + lp->b_off, addr, nw);
		addr = (u_int8_t *)addr + nw;
		len -= nw;
		lp->b_off += nw;

		/* If we fill the buffer, flush it. */
		if (lp->b_off == sizeof(lp->buf) &&
		    (ret = __log_write(dblp, lp->buf, sizeof(lp->buf))) != 0)
			return (ret);
	}
	return (0);
}

/*
 * __log_write --
 *	Write the log buffer to disk.
 */
static int
__log_write(dblp, addr, len)
	DB_LOG *dblp;
	void *addr;
	u_int32_t len;
{
	LOG *lp;
	ssize_t nw;
	int ret;

	/*
	 * If we haven't opened the log file yet or the current one
	 * has changed, acquire a new log file.
	 */
	lp = dblp->lp;
	if (dblp->lfd == -1 || dblp->lfname != lp->lsn.file)
		if ((ret = __log_newfd(dblp)) != 0)
			return (ret);

	/*
	 * Seek to the offset in the file (someone may have written it
	 * since we last did).
	 */
	if ((ret = __db_lseek(dblp->lfd, 0, 0, lp->w_off, SEEK_SET)) != 0)
		return (ret);
	if ((ret = __db_write(dblp->lfd, addr, len, &nw)) != 0)
		return (ret);
	if (nw != (int32_t)len)
		return (EIO);

	/* Update the seek offset and reset the buffer offset. */
	lp->b_off = 0;
	lp->w_off += len;
	lp->written += len;

	return (0);
}

/*
 * log_file --
 *	Map a DB_LSN to a file name.
 */
int
log_file(dblp, lsn, namep, len)
	DB_LOG *dblp;
	const DB_LSN *lsn;
	char *namep;
	size_t len;
{
	int ret;
	char *p;

	LOCK_LOGREGION(dblp);

	ret = __log_name(dblp, lsn->file, &p);

	UNLOCK_LOGREGION(dblp);

	if (ret != 0)
		return (ret);

	/* Check to make sure there's enough room and copy the name. */
	if (len < strlen(p)) {
		*namep = '\0';
		return (ENOMEM);
	}
	(void)strcpy(namep, p);
	free(p);

	return (0);
}

/*
 * __log_newfd --
 *	Acquire a file descriptor for the current log file.
 */
static int
__log_newfd(dblp)
	DB_LOG *dblp;
{
	int ret;
	char *p;

	/* Close any previous file descriptor. */
	if (dblp->lfd != -1) {
		(void)__db_close(dblp->lfd);
		dblp->lfd = -1;
	}

	/* Get the path of the new file and open it. */
	dblp->lfname = dblp->lp->lsn.file;
	if ((ret = __log_name(dblp, dblp->lfname, &p)) != 0)
		return (ret);
	if ((ret = __db_fdopen(p,
	    DB_CREATE | DB_SEQUENTIAL,
	    DB_CREATE | DB_SEQUENTIAL,
	    dblp->lp->persist.mode, &dblp->lfd)) != 0)
		__db_err(dblp->dbenv,
		    "log_put: %s: %s", p, strerror(ret));
	FREES(p);
	return (ret);
}

/*
 * __log_name --
 *	Return the log name for a particular file.
 *
 * PUBLIC: int __log_name __P((DB_LOG *, int, char **));
 */
int
__log_name(dblp, fileno, namep)
	DB_LOG *dblp;
	char **namep;
	int fileno;
{
	char name[sizeof(LFNAME) + 10];

	(void)snprintf(name, sizeof(name), LFNAME, fileno);
	return (__db_appname(dblp->dbenv,
	    DB_APP_LOG, dblp->dir, name, NULL, namep));
}
