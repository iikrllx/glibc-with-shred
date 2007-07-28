/* Copyright (C) 2003, 2004, 2006, 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Paul Mackerras <paulus@au.ibm.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _LOWLEVELLOCK_H
#define _LOWLEVELLOCK_H	1

#include <time.h>
#include <sys/param.h>
#include <bits/pthreadtypes.h>
#include <atomic.h>

#ifndef __NR_futex
# define __NR_futex		221
#endif
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_OP_CLEAR_WAKE_IF_GT_ONE	((4 << 24) | 1)
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_PRIVATE_FLAG	128

/* Values for 'private' parameter of locking macros.  Yes, the
   definition seems to be backwards.  But it is not.  The bit will be
   reversed before passing to the system call.  */
#define LLL_PRIVATE	0
#define LLL_SHARED	FUTEX_PRIVATE_FLAG

#if !defined NOT_IN_libc || defined IS_IN_rtld
/* In libc.so or ld.so all futexes are private.  */
# ifdef __ASSUME_PRIVATE_FUTEX
#  define __lll_private_flag(fl, private) \
  ((fl) | FUTEX_PRIVATE_FLAG)
# else
#  define __lll_private_flag(fl, private) \
  ((fl) | THREAD_GETMEM (THREAD_SELF, header.private_futex))
# endif
#else
# ifdef __ASSUME_PRIVATE_FUTEX
#  define __lll_private_flag(fl, private) \
  (((fl) | FUTEX_PRIVATE_FLAG) ^ (private))
# else
#  define __lll_private_flag(fl, private) \
  (__builtin_constant_p (private)					      \
   ? ((private) == 0							      \
      ? ((fl) | THREAD_GETMEM (THREAD_SELF, header.private_futex))	      \
      : (fl))								      \
   : ((fl) | (((private) ^ FUTEX_PRIVATE_FLAG)				      \
	      & THREAD_GETMEM (THREAD_SELF, header.private_futex))))
# endif	      
#endif

/* Initializer for compatibility lock.	*/
#define LLL_MUTEX_LOCK_INITIALIZER (0)

#define lll_futex_wait(futexp, val, private) \
  lll_futex_timed_wait (futexp, val, NULL, private)

#define lll_futex_timed_wait(futexp, val, timespec, private) \
  ({									      \
    INTERNAL_SYSCALL_DECL (__err);					      \
    long int __ret;							      \
									      \
    __ret = INTERNAL_SYSCALL (futex, __err, 4, (futexp),		      \
			      __lll_private_flag (FUTEX_WAIT, private),	      \
			      (val), (timespec));			      \
    INTERNAL_SYSCALL_ERROR_P (__ret, __err) ? -__ret : __ret;		      \
  })

#define lll_futex_wake(futexp, nr, private) \
  ({									      \
    INTERNAL_SYSCALL_DECL (__err);					      \
    long int __ret;							      \
									      \
    __ret = INTERNAL_SYSCALL (futex, __err, 4, (futexp),		      \
			      __lll_private_flag (FUTEX_WAKE, private),	      \
			      (nr), 0);					      \
    INTERNAL_SYSCALL_ERROR_P (__ret, __err) ? -__ret : __ret;		      \
  })

#define lll_robust_mutex_dead(futexv) \
  do									      \
    {									      \
      INTERNAL_SYSCALL_DECL (__err);					      \
      int *__futexp = &(futexv);					      \
									      \
      atomic_or (__futexp, FUTEX_OWNER_DIED);				      \
      INTERNAL_SYSCALL (futex, __err, 4, __futexp, FUTEX_WAKE, 1, 0);	      \
    }									      \
  while (0)

/* Returns non-zero if error happened, zero if success.  */
#define lll_futex_requeue(futexp, nr_wake, nr_move, mutex, val) \
  ({									      \
    INTERNAL_SYSCALL_DECL (__err);					      \
    long int __ret;							      \
									      \
    __ret = INTERNAL_SYSCALL (futex, __err, 6,				      \
			      (futexp), FUTEX_CMP_REQUEUE, (nr_wake),	      \
			      (nr_move), (mutex), (val));		      \
    INTERNAL_SYSCALL_ERROR_P (__ret, __err);				      \
  })

/* Returns non-zero if error happened, zero if success.  */
#define lll_futex_wake_unlock(futexp, nr_wake, nr_wake2, futexp2, private) \
  ({									      \
    INTERNAL_SYSCALL_DECL (__err);					      \
    long int __ret;							      \
									      \
    __ret = INTERNAL_SYSCALL (futex, __err, 6, (futexp),		      \
			      __lll_private_flag (FUTEX_WAKE_OP, private),    \
			      (nr_wake), (nr_wake2), (futexp2),		      \
			      FUTEX_OP_CLEAR_WAKE_IF_GT_ONE);		      \
    INTERNAL_SYSCALL_ERROR_P (__ret, __err);				      \
  })
  
  
#ifdef UP
# define __lll_acq_instr	""
# define __lll_rel_instr	""
#else
# define __lll_acq_instr	"isync"
# ifdef _ARCH_PWR4
/*
 * Newer powerpc64 processors support the new "light weight" sync (lwsync)
 * So if the build is using -mcpu=[power4,power5,power5+,970] we can
 * safely use lwsync.
 */
#  define __lll_rel_instr	"lwsync"
# else
/*
 * Older powerpc32 processors don't support the new "light weight"
 * sync (lwsync).  So the only safe option is to use normal sync
 * for all powerpc32 applications.
 */
#  define __lll_rel_instr	"sync"
# endif
#endif

/* Set *futex to ID if it is 0, atomically.  Returns the old value */
#define __lll_robust_trylock(futex, id) \
  ({ int __val;								      \
     __asm __volatile ("1:	lwarx	%0,0,%2" MUTEX_HINT_ACQ "\n"	      \
		       "	cmpwi	0,%0,0\n"			      \
		       "	bne	2f\n"				      \
		       "	stwcx.	%3,0,%2\n"			      \
		       "	bne-	1b\n"				      \
		       "2:	" __lll_acq_instr			      \
		       : "=&r" (__val), "=m" (*futex)			      \
		       : "r" (futex), "r" (id), "m" (*futex)		      \
		       : "cr0", "memory");				      \
     __val;								      \
  })

#define lll_robust_mutex_trylock(lock, id) __lll_robust_trylock (&(lock), id)

/* Set *futex to 1 if it is 0, atomically.  Returns the old value */
#define __lll_trylock(futex) __lll_robust_trylock (futex, 1)

#define lll_mutex_trylock(lock)	__lll_trylock (&(lock))

/* Set *futex to 2 if it is 0, atomically.  Returns the old value */
#define __lll_cond_trylock(futex) __lll_robust_trylock (futex, 2)

#define lll_mutex_cond_trylock(lock)	__lll_cond_trylock (&(lock))


extern void __lll_lock_wait (int *futex) attribute_hidden;
extern int __lll_robust_lock_wait (int *futex) attribute_hidden;

#define lll_mutex_lock(lock) \
  (void) ({								      \
    int *__futex = &(lock);						      \
    if (__builtin_expect (atomic_compare_and_exchange_val_acq (__futex, 1, 0),\
			  0) != 0)					      \
      __lll_lock_wait (__futex);					      \
  })

#define lll_robust_mutex_lock(lock, id) \
  ({									      \
    int *__futex = &(lock);						      \
    int __val = 0;							      \
    if (__builtin_expect (atomic_compare_and_exchange_bool_acq (__futex, id,  \
								0), 0))	      \
      __val = __lll_robust_lock_wait (__futex);				      \
    __val;								      \
  })

#define lll_mutex_cond_lock(lock) \
  (void) ({								      \
    int *__futex = &(lock);						      \
    if (__builtin_expect (atomic_compare_and_exchange_val_acq (__futex, 2, 0),\
			  0) != 0)					      \
      __lll_lock_wait (__futex);					      \
  })

#define lll_robust_mutex_cond_lock(lock, id) \
  ({									      \
    int *__futex = &(lock);						      \
    int __val = 0;							      \
    int __id = id | FUTEX_WAITERS;					      \
    if (__builtin_expect (atomic_compare_and_exchange_bool_acq (__futex, __id,\
								0), 0))	      \
      __val = __lll_robust_lock_wait (__futex);				      \
    __val;								      \
  })


extern int __lll_timedlock_wait
  (int *futex, const struct timespec *) attribute_hidden;
extern int __lll_robust_timedlock_wait
  (int *futex, const struct timespec *) attribute_hidden;

#define lll_mutex_timedlock(lock, abstime) \
  ({									      \
    int *__futex = &(lock);						      \
    int __val = 0;							      \
    if (__builtin_expect (atomic_compare_and_exchange_val_acq (__futex, 1, 0),\
			  0) != 0)					      \
      __val = __lll_timedlock_wait (__futex, abstime);			      \
    __val;								      \
  })

#define lll_robust_mutex_timedlock(lock, abstime, id) \
  ({									      \
    int *__futex = &(lock);						      \
    int __val = 0;							      \
    if (__builtin_expect (atomic_compare_and_exchange_bool_acq (__futex, id,  \
								0), 0))	      \
      __val = __lll_robust_timedlock_wait (__futex, abstime);		      \
    __val;								      \
  })

#define lll_mutex_unlock(lock) \
  ((void) ({								      \
    int *__futex = &(lock);						      \
    int __val = atomic_exchange_rel (__futex, 0);			      \
    if (__builtin_expect (__val > 1, 0))				      \
      lll_futex_wake (__futex, 1, LLL_SHARED);				      \
  }))

#define lll_robust_mutex_unlock(lock) \
  ((void) ({								      \
    int *__futex = &(lock);						      \
    int __val = atomic_exchange_rel (__futex, 0);			      \
    if (__builtin_expect (__val & FUTEX_WAITERS, 0))			      \
      lll_futex_wake (__futex, 1, LLL_SHARED);				      \
  }))

#define lll_mutex_unlock_force(lock) \
  ((void) ({								      \
    int *__futex = &(lock);						      \
    *__futex = 0;							      \
    __asm __volatile (__lll_rel_instr ::: "memory");			      \
    lll_futex_wake (__futex, 1, LLL_SHARED);				      \
  }))

#define lll_mutex_islocked(futex) \
  (futex != 0)


/* Our internal lock implementation is identical to the binary-compatible
   mutex implementation. */

/* Type for lock object.  */
typedef int lll_lock_t;

/* Initializers for lock.  */
#define LLL_LOCK_INITIALIZER		(0)
#define LLL_LOCK_INITIALIZER_LOCKED	(1)

/* The states of a lock are:
    0  -  untaken
    1  -  taken by one user
   >1  -  taken by more users */

#define lll_trylock(lock)	lll_mutex_trylock (lock)
#define lll_lock(lock)		lll_mutex_lock (lock)
#define lll_unlock(lock)	lll_mutex_unlock (lock)
#define lll_islocked(lock)	lll_mutex_islocked (lock)

/* The kernel notifies a process which uses CLONE_CLEARTID via futex
   wakeup when the clone terminates.  The memory location contains the
   thread ID while the clone is running and is reset to zero
   afterwards.	*/
#define lll_wait_tid(tid) \
  do {									      \
    __typeof (tid) __tid;						      \
    while ((__tid = (tid)) != 0)					      \
      lll_futex_wait (&(tid), __tid, LLL_SHARED);			      \
  } while (0)

extern int __lll_timedwait_tid (int *, const struct timespec *)
     attribute_hidden;

#define lll_timedwait_tid(tid, abstime) \
  ({									      \
    int __res = 0;							      \
    if ((tid) != 0)							      \
      __res = __lll_timedwait_tid (&(tid), (abstime));			      \
    __res;								      \
  })


/* Conditional variable handling.  */

extern void __lll_cond_wait (pthread_cond_t *cond)
     attribute_hidden;
extern int __lll_cond_timedwait (pthread_cond_t *cond,
				 const struct timespec *abstime)
     attribute_hidden;
extern void __lll_cond_wake (pthread_cond_t *cond)
     attribute_hidden;
extern void __lll_cond_broadcast (pthread_cond_t *cond)
     attribute_hidden;

#define lll_cond_wait(cond) \
  __lll_cond_wait (cond)
#define lll_cond_timedwait(cond, abstime) \
  __lll_cond_timedwait (cond, abstime)
#define lll_cond_wake(cond) \
  __lll_cond_wake (cond)
#define lll_cond_broadcast(cond) \
  __lll_cond_broadcast (cond)

#endif	/* lowlevellock.h */
