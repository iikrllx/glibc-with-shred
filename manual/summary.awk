# awk script to create summary.texinfo from the library texinfo files.
# Copyright (C) 1992-2017 Free Software Foundation, Inc.
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
# <http://www.gnu.org/licenses/>.

# This script recognizes sequences that look like:
#	@comment HEADER.h
#	@comment STANDARD
#	@def... ITEM | @item ITEM | @vindex ITEM

BEGIN { header = 0;
nameword["@defun"]=1
nameword["@defunx"]=1
nameword["@defmac"]=1
nameword["@defmacx"]=1
nameword["@defspec"]=1
nameword["@defspecx"]=1
nameword["@defvar"]=1
nameword["@defvarx"]=1
nameword["@defopt"]=1
nameword["@defoptx"]=1
nameword["@deffn"]=2
nameword["@deffnx"]=2
nameword["@defvr"]=2
nameword["@defvrx"]=2
nameword["@deftp"]=2
nameword["@deftpx"]=2
nameword["@deftypefun"]=2
nameword["@deftypefunx"]=2
nameword["@deftypevar"]=2
nameword["@deftypevarx"]=2
nameword["@deftypefn"]=3
nameword["@deftypefnx"]=3
nameword["@deftypevr"]=3
nameword["@deftypevrx"]=3
firstword["@defun"]=1
firstword["@defunx"]=1
firstword["@defmac"]=1
firstword["@defmacx"]=1
firstword["@defspec"]=1
firstword["@defspecx"]=1
firstword["@defvar"]=1
firstword["@defvarx"]=1
firstword["@defopt"]=1
firstword["@defoptx"]=1
firstword["@deffn"]=2
firstword["@deffnx"]=2
firstword["@defvr"]=2
firstword["@defvrx"]=2
firstword["@deftp"]=2
firstword["@deftpx"]=2
firstword["@deftypefun"]=1
firstword["@deftypefunx"]=1
firstword["@deftypevar"]=1
firstword["@deftypevarx"]=1
firstword["@deftypefn"]=2
firstword["@deftypefnx"]=2
firstword["@deftypevr"]=2
firstword["@deftypevrx"]=2
nameword["@item"]=1
firstword["@item"]=1
nameword["@itemx"]=1
firstword["@itemx"]=1
nameword["@vindex"]=1
firstword["@vindex"]=1

print "@c DO NOT EDIT THIS FILE!"
print "@c This file is generated by summary.awk from the Texinfo sources."
}

$1 == "@node" { node=$2;
		for (i = 3; i <= NF; ++i)
		 { node=node " " $i; if ( $i ~ /,/ ) break; }
		sub (/,[, ]*$/, "", node);
	      }

$1 == "@comment" && $2 ~ /\.h$/ { header="@file{" $2 "}";
				  for (i = 3; i <= NF; ++i)
				    header=header ", @file{" $i "}"
				}

$1 == "@comment" && $2 == "(none)" { header = -1; }

$1 == "@comment" && header != 0 { std=$2;
				  for (i=3;i<=NF;++i) std=std " " $i }

header != 0 && $1 ~ /@def|@item|@vindex/ \
	{ defn=""; name=""; curly=0; n=1;
	  for (i = 2; i <= NF; ++i) {
	    if ($i ~ /^{/ && $i !~ /}/) {
	      curly=1
	      word=substr ($i, 2, length ($i))
	    }
	    else {
	      if (curly) {
	        if ($i ~ /}$/) {
		  curly=0
		  word=word " " substr ($i, 1, length ($i) - 1)
	        } else
		  word=word " " $i
	      }
	      # Handle a single word in braces.
	      else if ($i ~ /^{.*}$/)
		word=substr ($i, 2, length ($i) - 2)
	      else
	        word=$i
	      if (!curly) {
		if (n >= firstword[$1])
		  defn=defn " " word
		if (n == nameword[$1])
		  name=word
		++n
	      }
	    }
	  }
	  printf "@comment %s%c", name, 12 # FF
	  printf "@item%s%c%c", defn, 12, 12
	  if (header != -1) printf "%s ", header;
	  printf "(%s):  @ref{%s}.%c\n", std, node, 12;
	  header = 0 }
