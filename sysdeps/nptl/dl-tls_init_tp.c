/* Completion of TCB initialization after TLS_INIT_TP.  NPTL version.
   Copyright (C) 2020-2021 Free Software Foundation, Inc.
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
   <https://www.gnu.org/licenses/>.  */

#include <kernel-features.h>
#include <ldsodefs.h>
#include <list.h>
#include <nptl/pthreadP.h>
#include <tls.h>

#ifndef __ASSUME_SET_ROBUST_LIST
bool __nptl_set_robust_list_avail __attribute__ ((nocommon));
rtld_hidden_data_def (__nptl_set_robust_list_avail)
#endif

void
__tls_init_tp (void)
{
  /* Set up thread stack list management.  */
  INIT_LIST_HEAD (&GL (dl_stack_used));
  INIT_LIST_HEAD (&GL (dl_stack_user));
  list_add (&THREAD_SELF->list, &GL (dl_stack_user));

   /* Early initialization of the TCB.   */
   struct pthread *pd = THREAD_SELF;
   pd->tid = INTERNAL_SYSCALL_CALL (set_tid_address, &pd->tid);
   THREAD_SETMEM (pd, specific[0], &pd->specific_1stblock[0]);
   THREAD_SETMEM (pd, user_stack, true);

  /* Initialize the robust mutex data.  */
  {
#if __PTHREAD_MUTEX_HAVE_PREV
    pd->robust_prev = &pd->robust_head;
#endif
    pd->robust_head.list = &pd->robust_head;
    pd->robust_head.futex_offset = (offsetof (pthread_mutex_t, __data.__lock)
                                    - offsetof (pthread_mutex_t,
                                                __data.__list.__next));
    int res = INTERNAL_SYSCALL_CALL (set_robust_list, &pd->robust_head,
                                     sizeof (struct robust_list_head));
    if (!INTERNAL_SYSCALL_ERROR_P (res))
      {
#ifndef __ASSUME_SET_ROBUST_LIST
        __nptl_set_robust_list_avail = true;
#endif
      }
  }

  /* Set initial thread's stack block from 0 up to __libc_stack_end.
     It will be bigger than it actually is, but for unwind.c/pt-longjmp.c
     purposes this is good enough.  */
  THREAD_SETMEM (pd, stackblock_size, (size_t) __libc_stack_end);
}
