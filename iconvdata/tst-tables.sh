#!/bin/sh
# Copyright (C) 2000 Free Software Foundation, Inc.
# This file is part of the GNU C Library.
# Contributed by Bruno Haible <haible@clisp.cons.org>, 2000.
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
# License along with the GNU C Library; see the file COPYING.LIB.  If not,
# write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

# Checks that the iconv() implementation (in both directions) for the
# stateless encodings agrees with the corresponding charmap table.

common_objpfx=$1
objpfx=$2

status=0

cat <<EOF |
  # Single-byte and other "small" encodings come here.
  # Keep this list in the same order as gconv-modules.
  #
  # charset name    table name          comment
  ASCII             ANSI_X3.4-1968
  ISO646-GB         BS_4730
  ISO646-CA         CSA_Z243.4-1985-1
  ISO646-CA2        CSA_Z243.4-1985-2
  ISO646-DE         DIN_66003
  ISO646-DK         DS_2089
  ISO646-ES         ES
  ISO646-ES2        ES2
  ISO646-CN         GB_1988-80
  ISO646-IT         IT
  ISO646-JP         JIS_C6220-1969-RO
  ISO646-JP-OCR-B   JIS_C6229-1984-B
  ISO646-YU         JUS_I.B1.002
  ISO646-KR         KSC5636
  ISO646-HU         MSZ_7795.3
  ISO646-CU         NC_NC00-10
  ISO646-FR         NF_Z_62-010
  ISO646-FR1        NF_Z_62-010_1973
  ISO646-NO         NS_4551-1
  ISO646-NO2        NS_4551-2
  ISO646-PT         PT
  ISO646-PT2        PT2
  ISO646-SE         SEN_850200_B
  ISO646-SE2        SEN_850200_C
  ISO-8859-1
  ISO-8859-2
  ISO-8859-3
  ISO-8859-4
  ISO-8859-5
  ISO-8859-6
  ISO-8859-7
  ISO-8859-8
  ISO-8859-9
  ISO-8859-10
  #ISO-8859-11                          No corresponding table, nonstandard
  ISO-8859-13
  ISO-8859-14
  ISO-8859-15
  ISO-8859-16
  T.61-8BIT
  ISO_6937
  #ISO_6937-2        ISO-IR-90          Handling of combining marks is broken
  KOI-8
  KOI8-R
  LATIN-GREEK
  LATIN-GREEK-1
  HP-ROMAN8
  EBCDIC-AT-DE
  EBCDIC-AT-DE-A
  EBCDIC-CA-FR
  EBCDIC-DK-NO
  EBCDIC-DK-NO-A
  EBCDIC-ES
  EBCDIC-ES-A
  EBCDIC-ES-S
  EBCDIC-FI-SE
  EBCDIC-FI-SE-A
  EBCDIC-FR
  EBCDIC-IS-FRISS
  EBCDIC-IT
  EBCDIC-PT
  EBCDIC-UK
  EBCDIC-US
  IBM037
  IBM038
  IBM256
  IBM273
  IBM274
  IBM275
  IBM277
  IBM278
  IBM280
  IBM281
  IBM284
  IBM285
  IBM290
  IBM297
  IBM420
  IBM423
  IBM424
  IBM437
  IBM500
  IBM850
  IBM851
  IBM852
  IBM855
  IBM857
  IBM860
  IBM861
  IBM862
  IBM863
  IBM864
  IBM865
  IBM866
  IBM868
  IBM869
  IBM870
  IBM871
  IBM875
  IBM880
  IBM891
  IBM903
  IBM904
  IBM905
  IBM918
  IBM1004
  IBM1026
  IBM1047
  CP1250
  CP1251
  CP1252
  CP1253
  CP1254
  CP1255
  CP1256
  CP1257
  CP1258
  IBM874
  CP737
  CP775
  MACINTOSH
  IEC_P27-1
  ASMO_449
  ISO-IR-99         ANSI_X3.110-1983
  ISO-IR-139        CSN_369103
  CWI
  DEC-MCS
  ECMA-CYRILLIC
  ISO-IR-153        GOST_19768-74
  GREEK-CCITT
  GREEK7
  GREEK7-OLD
  INIS
  INIS-8
  INIS-CYRILLIC
  ISO_2033          ISO_2033-1983
  ISO_5427
  ISO_5427-EXT
  #ISO_5428                             Handling of combining marks is broken
  ISO_10367-BOX
  MAC-IS
  MAC-UK
  NATS-DANO
  NATS-SEFI
  WIN-SAMI-2        SAMI-WS2
  ISO-IR-197
  TIS-620
  KOI8-U
  #ISIRI-3342                         This charset concept is completely broken
  #
  # Multibyte encodings come here
  #
  SJIS
  EUC-KR
  CP949
  JOHAB
  BIG5
  BIG5HKSCS
  EUC-JP
  EUC-CN            GB2312
  GBK
  EUC-TW
  GB18030
  #
  # Stateful encodings not testable this way
  #
  #ISO-2022-JP
  #ISO-2022-JP-2
  #ISO-2022-KR
  #ISO-2022-CN
  #ISO-2022-CN-EXT
  #
EOF
while read charset charmap; do
  if test "$charset" = GB18030; then echo "This might take a while" 1>&2; fi
  case ${charset} in \#*) continue;; esac
  echo -n "Testing ${charset}" 1>&2
  if ./tst-table.sh ${common_objpfx} ${objpfx} ${charset} ${charmap}; then
    echo 1>&2
  else
    echo "failed: ./tst-table.sh ${common_objpfx} ${objpfx} ${charset} ${charmap}"
    echo " *** FAILED ***" 1>&2
    exit 1
  fi
done

exit $?
