/* Copyright (C) 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

/*
 * ISO/IEC 9945-1:1996 6.7: Asynchronous Input and Output
 */

#ifndef _AIO_H
#define _AIO_H	1

#include <features.h>
#include <fcntl.h>
#include <signal.h>
#define __need_timespec
#include <time.h>
#include <sys/types.h>

__BEGIN_DECLS

/* Asynchronous I/O control block.  */
struct aiocb
{
  int aio_fildes;		/* File desriptor.  */
  int aio_lio_opcode;		/* Operation to be performed.  */
  int aio_reqprio;		/* Request priority offset.  */
  volatile void *aio_buf;	/* Location of buffer.  */
  size_t aio_nbytes;		/* Length of transfer.  */
  struct sigevent aio_sigevent;	/* Signal number and value.  */

  /* Internal members.  */
  struct aiocb *__next_prio;
  int __abs_prio;
  int __policy;
  int __error_code;
  __ssize_t __return_value;

#ifndef __USE_FILE_OFFSET64
  __off_t aio_offset;		/* File offset.  */
  char __pad[sizeof (__off64_t) - sizeof (__off_t)];
#else
  __off64_t aio_offset;		/* File offset.  */
#endif
  char __unused[32];
};

/* The same for the 64bit offsets.  */
#ifdef __USE_LARGEFILE64
struct aiocb64
{
  int aio_fildes;		/* File desriptor.  */
  int aio_lio_opcode;		/* Operation to be performed.  */
  int aio_reqprio;		/* Request priority offset.  */
  volatile void *aio_buf;	/* Location of buffer.  */
  size_t aio_nbytes;		/* Length of transfer.  */
  struct sigevent aio_sigevent;	/* Signal number and value.  */

  /* Internal members.  */
  int __abs_prio;
  int __policy;
  int __error_code;
  __ssize_t __return_value;

  __off64_t aio_offset;		/* File offset.  */
  char __unused[32];
};
#endif


#ifdef __USE_GNU
/* To customize the implementation one can use the following struct.
   This implementation follows the one in Irix.  */
struct aioinit
  {
    int aio_threads;		/* Maximal number of threads.  */
    int aio_num;		/* Number of expected simultanious requests. */
    int aio_locks;		/* Not used.  */
    int aio_usedba;		/* Not used.  */
    int aio_debug;		/* Not used.  */
    int aio_numusers;		/* Not used.  */
    int aio_reserved[2];
  };
#endif


/* Return values of cancelation function.  */
enum
{
  AIO_CANCELED,
#define AIO_CANCELED AIO_CANCELED
  AIO_NOTCANCELED,
#define AIO_NOTCANCELED AIO_NOTCANCELED
  AIO_ALLDONE
#define AIO_ALLDONE AIO_ALLDONE
};


/* Operation codes for `aio_lio_opcode'.  */
enum
{
  LIO_READ,
#define LIO_READ LIO_READ
  LIO_WRITE,
#define LIO_WRITE LIO_WRITE
  LIO_NOP
#define LIO_NOP LIO_NOP
};


/* Synchronization options for `lio_listio' function.  */
enum
{
  LIO_WAIT,
#define LIO_WAIT LIO_WAIT
  LIO_NOWAIT
#define LIO_NOWAIT LIO_NOWAIT
};


/* Allow user to specify optimization.  */
#ifdef __USE_GNU
extern void __aio_init __P ((__const struct aioinit *__init));
extern void aio_init __P ((__const struct aioinit *__init));
#endif


/* Enqueue read request for given number of bytes and the given priority.  */
#ifndef __USE_FILE_OFFSET64
extern int aio_read __P ((struct aiocb *__aiocbp));
#else
extern int aio_read __P ((struct aiocb *__aiocbp)) __asm__ ("aio_read64");
#endif
#ifdef __USE_LARGEFILE64
extern int aio_read64 __P ((struct aiocb64 *__aiocbp));
#endif

/* Enqueue write request for given number of bytes and the given priority.  */
#ifndef __USE_FILE_OFFSET64
extern int aio_write __P ((struct aiocb *__aiocbp));
#else
extern int aio_write __P ((struct aiocb *__aiocbp)) __asm__ ("aio_write64");
#endif
#ifdef __USE_LARGEFILE64
extern int aio_write64 __P ((struct aiocb64 *__aiocbp));
#endif


/* Initiate list of I/O requests.  */
#ifndef __USE_FILE_OFFSET64
extern int lio_listio __P ((int __mode, struct aiocb *__const __list[],
			    int __nent, struct sigevent *__sig));
#else
extern int lio_listio __P ((int __mode, struct aiocb *__const __list[],
			    int __nent, struct sigevent *__sig))
     __asm__ ("lio_listio64");
#endif
#ifdef __USE_LARGEFILE64
extern int lio_listio64 __P ((int __mode, struct aiocb64 *__const __list[],
			      int __nent, struct sigevent *__sig));
#endif


/* Retrieve error status associated with AIOCBP.  */
#ifndef __USE_FILE_OFFSET64
extern int aio_error __P ((__const struct aiocb *__aiocbp));
#else
extern int aio_error __P ((__const struct aiocb *__aiocbp))
     __asm__ ("aio_error64");;
#endif
#ifdef __USE_LARGEFILE64
extern int aio_error64 __P ((__const struct aiocb64 *__aiocbp));
#endif


/* Return status associated with AIOCBP.  */
#ifndef __USE_FILE_OFFSET64
extern __ssize_t aio_return __P ((struct aiocb *__aiocbp));
#else
extern __ssize_t aio_return __P ((struct aiocb *__aiocbp))
     __asm__ ("aio_return64");
#endif
#ifdef __USE_LARGEFILE64
extern __ssize_t aio_return64 __P ((struct aiocb64 *__aiocbp));
#endif


/* Try to cancel asynchronous I/O requests outstanding against file
   descriptot FILDES.  */
#ifndef __USE_FILE_OFFSET64
extern int aio_cancel __P ((int __fildes, struct aiocb *__aiocbp));
#else
extern int aio_cancel __P ((int __fildes, struct aiocb *__aiocbp))
     __asm__ ("aio_cancel64");
#endif
#ifdef __USE_LARGEFILE64
extern int aio_cancel64 __P ((int __fildes, struct aiocb64 *__aiocbp));
#endif


/* Suspend calling thread until at least one of the asynchronous I/O
   operations referenced by LIST has completed.  */
#ifndef __USE_FILE_OFFSET64
extern int aio_suspend __P ((__const struct aiocb *__const __list[],
			     int __nent, __const struct timespec *__timeout));
#else
extern int aio_suspend __P ((__const struct aiocb *__const __list[],
			     int __nent, __const struct timespec *__timeout))
     __asm__ ("aio_suspend64");
#endif
#ifdef __USE_LARGEFILE64
extern int aio_suspend64 __P ((__const struct aiocb64 *__const __list[],
			       int __nent,
			       __const struct timespec *__timeout));
#endif


/* Force all operations associated with file desriptor described by
   `aio_fildes' member of AIOCBP.  */
#ifndef __USE_FILE_OFFSET64
extern int aio_fsync __P ((int __op, struct aiocb *__aiocbp));
#else
extern int aio_fsync __P ((int __op, struct aiocb *__aiocbp))
     __asm__ ("aio_fsync64");
#endif
#ifdef __USE_LARGEFILE64
extern int aio_fsync64 __P ((int __op, struct aiocb64 *__aiocbp));
#endif


__END_DECLS

#endif /* aio.h */
