# awk script to generate errlist-compat.c
# Copyright (C) 2002 Free Software Foundation, Inc.
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
# License along with the GNU C Library; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307 USA.

#
# This script takes the Versions file as input and looks for #errlist-compat
# magic comments, which have the form:
#	#errlist-compat NNN
# where NNN is the number of elements in the sys_errlist for that version set.
# We need the awk variable `maxerr' defined to the current size of sys_errlist.
#
# If there is no magic comment matching the current size, we barf.
# Otherwise we generate code (errlist-compat.c) to define all the
# necessary compatibility symbols for older, smaller versions of sys_errlist.
#

BEGIN { highest = 0 }

# These two rules catch the Versions file contents.
NF == 2 && $2 == "{" { last_version = $1; next }
$1 == "#errlist-compat" {
  n = $2 + 0;
  if (n < 100) {
    print "*** this line seems bogus:", $0 > "/dev/stderr";
    exit 1;
  }
  version[n] = last_version;
  if (n > highest)
    highest = n;
  next;
}

END {
  count = maxerr + 1;

  if (highest != count) {
    printf "*** errlist.c count %d vs Versions sys_errlist@%s count %d\n", \
      count, version[highest], highest > "/dev/stderr";
    exit 1;
  }

  lastv = "";
  for (n = 0; n <= count; ++n)
    if (n in version) {
      v = version[n];
      gsub(/[^A-Z0-9_]/, "_", v);
      if (lastv != "")
	compat[lastv] = v;
      lastv = v;
      vcount[v] = n;
    }

  print "/* This file was generated by errlist-compat.awk; DO NOT EDIT!  */\n";
  print "#include <shlib-compat.h>\n";

  for (old in compat) {
    new = compat[old];
    n = vcount[old];
    printf "#if SHLIB_COMPAT (libc, %s, %s)\n", old, new;
    printf "# include <bits/wordsize.h>\n";
    printf "extern const char *const __sys_errlist_%s[];\n", old;
    printf "const int __sys_nerr_%s = %d;\n", old, n;
    printf "strong_alias (_sys_errlist_internal, __sys_errlist_%s)\n", old;
    printf "declare_symbol (__sys_errlist_%s, object, __WORDSIZE/8*%d)\n", \
      old, n;
    printf "compat_symbol (libc, __sys_errlist_%s, sys_errlist, %s);\n", \
      old, old;
    printf "compat_symbol (libc, __sys_nerr_%s, sys_nerr, %s);\n", old, old;

    printf "extern const char *const ___sys_errlist_%s[];\n", old;
    printf "extern const int __sys_nerr_%s;\n", old;
    printf "strong_alias (__sys_errlist_%s, ___sys_errlist_%s)\n", old, old;
    printf "strong_alias (__sys_nerr_%s, ___sys_nerr_%s)\n", old, old;
    printf "compat_symbol (libc, ___sys_errlist_%s, _sys_errlist, %s);\n", \
      old, old;
    printf "compat_symbol (libc, ___sys_nerr_%s, _sys_nerr, %s);\n", old, old;
    printf "#endif\n\n";
  }

  printf "\
extern const char *const __sys_errlist_internal[];\n\
extern const int __sys_nerr_internal;\n\
strong_alias (_sys_errlist_internal, __sys_errlist_internal)\n\
strong_alias (_sys_nerr_internal, __sys_nerr_internal)\n\
versioned_symbol (libc, _sys_errlist_internal, sys_errlist, %s);\n\
versioned_symbol (libc, __sys_errlist_internal, _sys_errlist, %s);\n\
versioned_symbol (libc, _sys_nerr_internal, sys_nerr, %s);\n\
versioned_symbol (libc, __sys_nerr_internal, _sys_nerr, %s);\n", \
    lastv, lastv, lastv, lastv;
}
