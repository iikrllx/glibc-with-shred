/* Checking macros for syslog functions.
   Copyright (C) 2005, 2007 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _SYS_SYSLOG_H
# error "Never include <bits/syslog.h> directly; use <sys/syslog.h> instead."
#endif


extern void __syslog_chk (int __pri, int __flag, __const char *__fmt, ...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

#ifdef __va_arg_pack
__extern_always_inline void
syslog (int __pri, __const char *__fmt, ...)
{
  return __syslog_chk (__pri, __USE_FORTIFY_LEVEL - 1, __fmt, __va_arg_pack ());
}
#elif !defined __cplusplus
# define syslog(pri, ...) \
  __syslog_chk (pri, __USE_FORTIFY_LEVEL - 1, __VA_ARGS__)
#endif


#ifdef __USE_BSD
extern void __vsyslog_chk (int __pri, int __flag, __const char *__fmt,
			   __gnuc_va_list __ap)
     __attribute__ ((__format__ (__printf__, 3, 0)));

__extern_always_inline void
vsyslog (int __pri, __const char *__fmt, __gnuc_va_list __ap)
{
  return __vsyslog_chk (__pri,  __USE_FORTIFY_LEVEL - 1, __fmt, __ap);
}
#endif
