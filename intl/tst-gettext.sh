#! /bin/sh
# Test of gettext functions.
# Copyright (C) 2000 Free Software Foundation, Inc.
# This file is part of the GNU C Library.
#
# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with the GNU C Library; see the file COPYING.LIB.  If
# not, write to the Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

common_objpfx=$1
objpfx=$2

GCONV_PATH=${common_objpfx}iconvdata
export GCONV_PATH
LOCPATH=${common_objpfx}localedata
export LOCPATH

# Generate the test data.
test -d ${objpfx}domaindir || mkdir ${objpfx}domaindir
# Create the locale directories.
test -d ${objpfx}domaindir/existing-locale || mkdir ${objpfx}domaindir/existing-locale
test -d ${objpfx}domaindir/existing-locale/LC_MESSAGES || mkdir ${objpfx}domaindir/existing-locale/LC_MESSAGES
test -d ${objpfx}domaindir/existing-locale/LC_TIME || mkdir ${objpfx}domaindir/existing-locale/LC_TIME

# Populate them.
msgfmt -o ${objpfx}domaindir/existing-locale/LC_MESSAGES/existing-domain.mo \
       ../po/de.po
msgfmt -o ${objpfx}domaindir/existing-locale/LC_TIME/existing-time-domain.mo \
       ../po/de.po

# Now run the test.
${common_objpfx}elf/ld.so --library-path $common_objpfx \
${objpfx}tst-gettext > ${objpfx}tst-gettext.out ${objpfx}domaindir

exit $?
