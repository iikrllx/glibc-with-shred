/* Checking macros for stdlib functions.
   Copyright (C) 2005 Free Software Foundation, Inc.
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

#ifndef _STDLIB_H
# error "Never include <bits/stdlib.h> directly; use <stdlib.h> instead."
#endif

extern char *__realpath_chk (__const char *__restrict __name,
			     char *__restrict __resolved,
			     size_t __resolvedlen) __THROW __wur;
extern char *__REDIRECT_NTH (__realpath_alias,
			     (__const char *__restrict __name,
			      char *__restrict __resolved), realpath) __wur;

extern __always_inline __wur char *
realpath (const char *__name, char *__resolved)
{
  if (__bos (__resolved) != (size_t) -1)
    return __realpath_chk (__name, __resolved, __bos (__resolved));

  return __realpath_alias (__name, __resolved);
}


extern int __ptsname_r_chk (int __fd, char *__buf, size_t __buflen,
			    size_t __nreal) __THROW __nonnull ((2));
extern int __REDIRECT_NTH (__ptsname_r_alias, (int __fd, char *__buf,
					       size_t __buflen), ptsname_r)
     __nonnull ((2));

extern __always_inline int
ptsname_r (int __fd, char *__buf, size_t __buflen)
{
  if (__bos (__buf) != (size_t) -1
      && (!__builtin_constant_p (__buflen) || __buflen > __bos (__buf)))
    return __ptsname_r_chk (__fd, __buf, __buflen, __bos (__buf));
  return __ptsname_r_alias (__fd, __buf, __buflen);
}


extern int __wctomb_chk (char *__s, wchar_t __wchar, size_t __buflen)
  __THROW __wur;
extern int __REDIRECT_NTH (__wctomb_alias, (char *__s, wchar_t __wchar),
			   wctomb) __wur;

extern __always_inline __wur int
wctomb (char *__s, wchar_t __wchar)
{
  /* We would have to include <limits.h> to get a definition of MB_LEN_MAX.
     But this would only disturb the namespace.  So we define our own
     version here.  */
#define __STDLIB_MB_LEN_MAX	16
#if defined MB_LEN_MAX && MB_LEN_MAX != __STDLIB_MB_LEN_MAX
# error "Assumed value of MB_LEN_MAX wrong"
#endif
  if (__bos (__s) != (size_t) -1 && __STDLIB_MB_LEN_MAX > __bos (__s))
    return __wctomb_chk (__s, __wchar, __bos (__s));
  return __wctomb_alias (__s, __wchar);
}
