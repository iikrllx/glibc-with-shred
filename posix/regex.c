/* Extended regular expression matching and search library.
   Copyright (C) 2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.

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

#ifdef _LIBC
/* We have to keep the namespace clean.  */
#  define regfree(preg) __regfree (preg)
#  define regexec(pr, st, nm, pm, ef) __regexec (pr, st, nm, pm, ef)
#  define regcomp(preg, pattern, cflags) __regcomp (preg, pattern, cflags)
#  define regerror(errcode, preg, errbuf, errbuf_size) \
	__regerror(errcode, preg, errbuf, errbuf_size)
#  define re_set_registers(bu, re, nu, st, en) \
	__re_set_registers (bu, re, nu, st, en)
#  define re_match_2(bufp, string1, size1, string2, size2, pos, regs, stop) \
	__re_match_2 (bufp, string1, size1, string2, size2, pos, regs, stop)
#  define re_match(bufp, string, size, pos, regs) \
	__re_match (bufp, string, size, pos, regs)
#  define re_search(bufp, string, size, startpos, range, regs) \
	__re_search (bufp, string, size, startpos, range, regs)
#  define re_compile_pattern(pattern, length, bufp) \
	__re_compile_pattern (pattern, length, bufp)
#  define re_set_syntax(syntax) __re_set_syntax (syntax)
#  define re_search_2(bufp, st1, s1, st2, s2, startpos, range, regs, stop) \
	__re_search_2 (bufp, st1, s1, st2, s2, startpos, range, regs, stop)
#  define re_compile_fastmap(bufp) __re_compile_fastmap (bufp)
#endif

#if _LIBC || __GNUC__ >= 3
# define BE(expr, val) __builtin_expect (expr, val)
#else
# define BE(expr, val) (expr)
#endif

#include "regcomp.c"
#include "regexec.c"
#include "regex_internal.c"
