/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1996, 1997
 *	Sleepycat Software.  All rights reserved.
 */
/*
 * Copyright (c) 1996
 *	The President and Fellows of Harvard University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#ifndef lint
static const char sccsid[] = "@(#)txn_rec.c	10.4 (Sleepycat) 7/2/97";
#endif /* not lint */

#ifndef NO_SYSTEM_INCLUDES
#include <sys/types.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "db_int.h"
#include "db_page.h"
#include "shqueue.h"
#include "txn.h"
#include "db_dispatch.h"
#include "db_am.h"
#include "common_ext.h"

/*
 * PUBLIC: int __txn_regop_recover
 * PUBLIC:     __P((DB_LOG *, DBT *, DB_LSN *, int, void *));
 */
int
__txn_regop_recover(logp, dbtp, lsnp, redo, info)
	DB_LOG *logp;
	DBT *dbtp;
	DB_LSN *lsnp;
	int redo;
	 void *info;
{
	__txn_regop_args *argp;
	int ret;

#ifdef DEBUG_RECOVER
	(void)__txn_regop_print(logp, dbtp, lsnp, redo, info);
#endif
	logp = logp;			/* XXX: Shut the compiler up. */
	redo = redo;

	if ((ret = __txn_regop_read(dbtp->data, &argp)) != 0)
		return (ret);

	switch (argp->opcode) {
	case TXN_COMMIT:
		if (__db_txnlist_find(info,
		    argp->txnid->txnid) == DB_NOTFOUND)
			__db_txnlist_add(info, argp->txnid->txnid);
		break;
	case TXN_PREPARE:	/* Nothing to do. */
	case TXN_BEGIN:
		/* Call find so that we update the maxid. */
		(void)__db_txnlist_find(info, argp->txnid->txnid);
		break;
	}

	*lsnp = argp->prev_lsn;
	free (argp);
	return (0);
}

/*
 * PUBLIC: int __txn_ckp_recover __P((DB_LOG *, DBT *, DB_LSN *, int, void *));
 */
int
__txn_ckp_recover(logp, dbtp, lsnp, redo, info)
	DB_LOG *logp;
	DBT *dbtp;
	DB_LSN *lsnp;
	int redo;
	void *info;
{
	__txn_ckp_args *argp;
	int ret;

#ifdef DEBUG_RECOVER
	__txn_ckp_print(logp, dbtp, lsnp, redo, info);
#endif
	logp = logp;			/* XXX: Shut the compiler up. */
	redo = redo;
	info = info;

	if ((ret = __txn_ckp_read(dbtp->data, &argp)) != 0)
		return (ret);

	*lsnp = argp->last_ckp;
	free(argp);
	return (1);
}
