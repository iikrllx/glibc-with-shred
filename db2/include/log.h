/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1996, 1997
 *	Sleepycat Software.  All rights reserved.
 *
 *	@(#)log.h	10.9 (Sleepycat) 9/23/97
 */

#ifndef _LOG_H_
#define	_LOG_H_

struct __fname;		typedef struct __fname FNAME;
struct __hdr;		typedef struct __hdr HDR;
struct __log;		typedef struct __log LOG;
struct __log_persist;	typedef struct __log_persist LOGP;

#define	MAXLFNAME	99999		/* Maximum log file name. */
#define	LFNAME		"log.%05d"	/* Log file name template. */

					/* Default log name. */
#define DB_DEFAULT_LOG_FILE	"__db_log.share"

#define	DEFAULT_MAX	(10 * 1048576)	/* 10 Mb. */

/* Macros to return per-process address, offsets. */
#define	ADDR(base, offset)	((void *)((u_int8_t *)((base)->addr) + offset))
#define	OFFSET(base, p)		((u_int8_t *)(p) - (u_int8_t *)(base)->addr)

/* Macros to lock/unlock the region and threads. */
#define	LOCK_LOGTHREAD(dblp)						\
	if (F_ISSET(dblp, DB_AM_THREAD))				\
		(void)__db_mutex_lock((dblp)->mutexp, -1,		\
		    (dblp)->dbenv == NULL ? NULL : (dblp)->dbenv->db_yield)
#define	UNLOCK_LOGTHREAD(dblp)						\
	if (F_ISSET(dblp, DB_AM_THREAD))				\
		(void)__db_mutex_unlock((dblp)->mutexp, -1);
#define	LOCK_LOGREGION(dblp)						\
	(void)__db_mutex_lock(&((RLAYOUT *)(dblp)->lp)->lock,		\
	    (dblp)->fd, (dblp)->dbenv == NULL ? NULL : (dblp)->dbenv->db_yield)
#define	UNLOCK_LOGREGION(dblp)						\
	(void)__db_mutex_unlock(&((RLAYOUT *)(dblp)->lp)->lock, (dblp)->fd)

/*
 * The per-process table that maps log file-id's to DB structures.
 */
typedef	struct __db_entry {
	DB	*dbp;			/* Associated DB structure. */
	int	refcount;		/* Reference counted. */
	int	deleted;		/* File was not found during open. */
} DB_ENTRY;

/*
 * DB_LOG
 *	Per-process log structure.
 */
struct __db_log {
/* These fields need to be protected for multi-threaded support. */
	db_mutex_t	*mutexp;	/* Mutex for thread protection. */

	DB_ENTRY *dbentry;		/* Recovery file-id mapping. */
#define	DB_GROW_SIZE	64
	u_int32_t dbentry_cnt;		/* Entries.  Grows by DB_GROW_SIZE. */

/*
 * These fields are always accessed while the region lock is held, so they do
 * not have to be protected by the thread lock as well OR, they are only used
 * when threads are not being used, i.e. most cursor operations are disallowed
 * on threaded logs.
 */
	u_int32_t lfname;		/* Log file "name". */
	int	  lfd;			/* Log file descriptor. */

	DB_LSN	  c_lsn;		/* Cursor: current LSN. */
	DBT	  c_dbt;		/* Cursor: return DBT structure. */
	int	  c_fd;			/* Cursor: file descriptor. */
	u_int32_t c_off;		/* Cursor: previous record offset. */
	u_int32_t c_len;		/* Cursor: current record length. */

/* These fields are not protected. */
	LOG	 *lp;			/* Address of the shared LOG. */

	DB_ENV	 *dbenv;		/* Reference to error information. */

	void     *maddr;		/* Address of mmap'd region. */
	void     *addr;			/* Address of shalloc() region. */
	int	  fd;			/* Region file descriptor. */

	char	 *dir;			/* Directory argument. */

	u_int32_t flags;		/* Support the DB_AM_XXX flags. */
};

/*
 * HDR --
 *	Log record header.
 */
struct __hdr {
	u_int32_t prev;			/* Previous offset. */
	u_int32_t cksum;		/* Current checksum. */
	u_int32_t len;			/* Current length. */
};

struct __log_persist {
	u_int32_t magic;		/* DB_LOGMAGIC */
	u_int32_t version;		/* DB_LOGVERSION */

	u_int32_t lg_max;		/* Maximum file size. */
	int	  mode;			/* Log file mode. */
};

/*
 * LOG --
 *	Shared log region.  One of these is allocated in shared memory,
 *	and describes the log.
 */
struct __log {
	RLAYOUT	  rlayout;		/* General region information. */

	LOGP	  persist;		/* Persistent information. */

	SH_TAILQ_HEAD(__fq) fq;		/* List of file names. */

	DB_LSN	  lsn;			/* LSN at current file offset. */
	DB_LSN	  c_lsn;		/* LSN of the last checkpoint. */
	DB_LSN	  s_lsn;		/* LSN of the last sync. */
	DB_LSN	  span_lsn;		/* LSN spanning buffer write. */

	u_int32_t len;			/* Length of the last record. */

	size_t	  b_off;		/* Current offset in the buffer. */
	u_int32_t w_off;		/* Current write offset in the file. */

	time_t	  chkpt;		/* Time of the last checkpoint. */
	u_int32_t written;		/* Bytes written since checkpoint. */

	u_int8_t buf[4 * 1024];		/* Log buffer. */
};

/*
 * FNAME --
 *	File name and id.
 */
struct __fname {
	SH_TAILQ_ENTRY q;		/* File name queue. */

	u_int16_t ref;			/* Reference count. */

	u_int32_t id;			/* Logging file id. */
	DBTYPE	  s_type;		/* Saved DB type. */

	u_int32_t fileid_off;		/* Unique file id offset. */

	size_t	  name_off;		/* Name offset. */
};

#include "log_auto.h"
#include "log_ext.h"
#endif /* _LOG_H_ */
