#!/bin/sh
# Test for getconf(1).
# Copyright (C) 2001-2020 Free Software Foundation, Inc.
# This file is part of the GNU C Library.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, see
# <https://www.gnu.org/licenses/>.

set -e

common_objpfx=$1; shift
run_getconf=$1; shift

logfile=$common_objpfx/posix/tst-getconf.out

rm -f $logfile
result=0
while read name; do
  printf %s "getconf $name: " >> $logfile
  ${run_getconf} "$name" < /dev/null 2>> $logfile >> $logfile
  if test $? -ne 0; then
    echo "*** $name FAILED" >> $logfile
    result=1
  fi
done <<EOF
AIO_LISTIO_MAX
AIO_MAX
AIO_PRIO_DELTA_MAX
ARG_MAX
ATEXIT_MAX
BC_BASE_MAX
BC_DIM_MAX
BC_SCALE_MAX
BC_STRING_MAX
CHILD_MAX
COLL_WEIGHTS_MAX
DELAYTIMER_MAX
EXPR_NEST_MAX
HOST_NAME_MAX
IOV_MAX
LINE_MAX
LOGIN_NAME_MAX
NGROUPS_MAX
MQ_OPEN_MAX
MQ_PRIO_MAX
OPEN_MAX
_POSIX_ADVISORY_INFO
_POSIX_BARRIERS
_POSIX_ASYNCHRONOUS_IO
_POSIX_BASE
_POSIX_C_LANG_SUPPORT
_POSIX_C_LANG_SUPPORT_R
_POSIX_CLOCK_SELECTION
_POSIX_CPUTIME
_POSIX_DEVICE_IO
_POSIX_DEVICE_SPECIFIC
_POSIX_DEVICE_SPECIFIC_R
_POSIX_FD_MGMT
_POSIX_FIFO
_POSIX_FILE_ATTRIBUTES
_POSIX_FILE_LOCKING
_POSIX_FILE_SYSTEM
_POSIX_FSYNC
_POSIX_JOB_CONTROL
_POSIX_MAPPED_FILES
_POSIX_MEMLOCK
_POSIX_MEMLOCK_RANGE
_POSIX_MEMORY_PROTECTION
_POSIX_MESSAGE_PASSING
_POSIX_MONOTONIC_CLOCK
_POSIX_MULTI_PROCESS
_POSIX_NETWORKING
_POSIX_PIPE
_POSIX_PRIORITIZED_IO
_POSIX_PRIORITY_SCHEDULING
_POSIX_READER_WRITER_LOCKS
_POSIX_REALTIME_SIGNALS
_POSIX_REGEXP
_POSIX_SAVED_IDS
_POSIX_SEMAPHORES
_POSIX_SHARED_MEMORY_OBJECTS
_POSIX_SHELL
_POSIX_SIGNALS
_POSIX_SINGLE_PROCESS
_POSIX_SPAWN
_POSIX_SPIN_LOCKS
_POSIX_SPORADIC_SERVER
_POSIX_SYNCHRONIZED_IO
_POSIX_SYSTEM_DATABASE
_POSIX_SYSTEM_DATABASE_R
_POSIX_THREAD_ATTR_STACKADDR
_POSIX_THREAD_ATTR_STACKSIZE
_POSIX_THREAD_CPUTIME
_POSIX_THREAD_PRIO_INHERIT
_POSIX_THREAD_PRIO_PROTECT
_POSIX_THREAD_PRIORITY_SCHEDULING
_POSIX_THREAD_PROCESS_SHARED
_POSIX_THREAD_SAFE_FUNCTIONS
_POSIX_THREAD_SPORADIC_SERVER
_POSIX_THREADS
_POSIX_TIMEOUTS
_POSIX_TIMERS
_POSIX_TRACE
_POSIX_TRACE_EVENT_FILTER
_POSIX_TRACE_INHERIT
_POSIX_TRACE_LOG
_POSIX_TYPED_MEMORY_OBJECTS
_POSIX_USER_GROUPS
_POSIX_USER_GROUPS_R
_POSIX_VERSION
_POSIX_V6_ILP32_OFF32
_POSIX_V6_ILP32_OFFBIG
_POSIX_V6_LP64_OFF64
_POSIX_V6_LPBIG_OFFBIG
_POSIX_V6_WIDTH_RESTRICTED_ENVS
POSIX2_C_BIND
POSIX2_C_DEV
POSIX2_C_VERSION
POSIX2_CHAR_TERM
POSIX2_FORT_DEV
POSIX2_FORT_RUN
POSIX2_LOCALEDEF
POSIX2_PBS
POSIX2_PBS_ACCOUNTING
POSIX2_PBS_LOCATE
POSIX2_PBS_MESSAGE
POSIX2_PBS_TRACK
POSIX2_SW_DEV
POSIX2_UPE
POSIX2_VERSION
_REGEX_VERSION
PAGE_SIZE
PAGESIZE
PTHREAD_DESTRUCTOR_ITERATIONS
PTHREAD_KEYS_MAX
PTHREAD_STACK_MIN
PTHREAD_THREADS_MAX
RE_DUP_MAX
RTSIG_MAX
SEM_NSEMS_MAX
SEM_VALUE_MAX
SIGQUEUE_MAX
STREAM_MAX
SYMLOOP_MAX
TIMER_MAX
TTY_NAME_MAX
TZNAME_MAX
_XBS5_ILP32_OFF32
_XBS5_ILP32_OFFBIG
_XBS5_LP64_OFF64
_XBS5_LPBIG_OFFBIG
_XOPEN_CRYPT
_XOPEN_ENH_I18N
_XOPEN_LEGACY
_XOPEN_REALTIME
_XOPEN_REALTIME_THREADS
_XOPEN_SHM
_XOPEN_UNIX
_XOPEN_VERSION
_XOPEN_XCU_VERSION
PATH
POSIX_V6_ILP32_OFF32_CFLAGS
POSIX_V6_ILP32_OFF32_LDFLAGS
POSIX_V6_ILP32_OFF32_LIBS
POSIX_V6_ILP32_OFF32_LINTFLAGS
POSIX_V6_ILP32_OFFBIG_CFLAGS
POSIX_V6_ILP32_OFFBIG_LDFLAGS
POSIX_V6_ILP32_OFFBIG_LIBS
POSIX_V6_ILP32_OFFBIG_LINTFLAGS
POSIX_V6_LP64_OFF64_CFLAGS
POSIX_V6_LP64_OFF64_LDFLAGS
POSIX_V6_LP64_OFF64_LIBS
POSIX_V6_LP64_OFF64_LINTFLAGS
POSIX_V6_LPBIG_OFFBIG_CFLAGS
POSIX_V6_LPBIG_OFFBIG_LDFLAGS
POSIX_V6_LPBIG_OFFBIG_LIBS
POSIX_V6_LPBIG_OFFBIG_LINTFLAGS
XBS5_ILP32_OFF32_CFLAGS
XBS5_ILP32_OFF32_LDFLAGS
XBS5_ILP32_OFF32_LIBS
XBS5_ILP32_OFF32_LINTFLAGS
XBS5_ILP32_OFFBIG_CFLAGS
XBS5_ILP32_OFFBIG_LDFLAGS
XBS5_ILP32_OFFBIG_LIBS
XBS5_ILP32_OFFBIG_LINTFLAGS
XBS5_LP64_OFF64_CFLAGS
XBS5_LP64_OFF64_LDFLAGS
XBS5_LP64_OFF64_LIBS
XBS5_LP64_OFF64_LINTFLAGS
XBS5_LPBIG_OFFBIG_CFLAGS
XBS5_LPBIG_OFFBIG_LDFLAGS
XBS5_LPBIG_OFFBIG_LIBS
XBS5_LPBIG_OFFBIG_LINTFLAGS
EOF

while read name; do
  printf %s "getconf $name /: " >> $logfile
  ${run_getconf} "$name" / < /dev/null 2>> $logfile >> $logfile
  if test $? -ne 0; then
    echo "*** $name FAILED" >> $logfile
    result=1
  fi
done <<EOF
FILESIZEBITS
LINK_MAX
MAX_CANON
MAX_INPUT
NAME_MAX
PATH_MAX
PIPE_BUF
POSIX_ALLOC_SIZE_MIN
POSIX_REC_INCR_XFER_SIZE
POSIX_REC_MAX_XFER_SIZE
POSIX_REC_MIN_XFER_SIZE
POSIX_REC_XFER_ALIGN
SYMLINK_MAX
_POSIX_CHOWN_RESTRICTED
_POSIX_NO_TRUNC
_POSIX_VDISABLE
_POSIX_ASYNC_IO
_POSIX_PRIO_IO
_POSIX_SYNC_IO
EOF

exit $result

# Preserve executable bits for this shell script.
Local Variables:
eval:(defun frobme () (set-file-modes buffer-file-name file-mode))
eval:(make-local-variable 'file-mode)
eval:(setq file-mode (file-modes (buffer-file-name)))
eval:(make-local-variable 'after-save-hook)
eval:(add-hook 'after-save-hook 'frobme)
End:
