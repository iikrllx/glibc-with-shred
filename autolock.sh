#! /bin/sh
# interlock - wrap program invocation in lock to allow
#             parallel builds to work.
# Written by Tom Tromey <tromey@cygnus.com>, Aug 10 1996
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

# Usage:
#   interlock lock-dir-name program args-to-program...

dirname="$1"
program="$2"

shift
shift

while (mkdir $dirname > /dev/null 2>&1 && exit 1 || exit 0); do
   # Wait a bit.
   sleep 1
done

# Race condition here: if interrupted after the loop but before this
# trap, the lock can be left around.
trap "rmdir $dirname > /dev/null 2>&1" 1 2 3 15

# We have the lock, so run the program.
$program ${1+"$@"}
ret=$?

# Release the lock.
rmdir $dirname > /dev/null 2>&1

exit $ret
