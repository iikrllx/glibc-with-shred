#! /bin/sh

common_objpfx=$1; shift
lang=$*

id=${PPID:-100}
here=`pwd`

# Run collation tests.
status=0
for l in $lang; do
  cns=`echo $l | sed 's/\(.*\)[.][^.]*/\1/'`
  LOCPATH=${common_objpfx}localedata GCONV_PATH=${common_objpfx}/iconvdata \
   LC_ALL=$l ${common_objpfx}elf/ld.so --library-path $common_objpfx \
   ${common_objpfx}localedata/collate-test $id < $cns.in \
   > ${common_objpfx}localedata/$cns.out || status=1
  cmp -s $cns.in ${common_objpfx}localedata/$cns.out || status=1

  LOCPATH=${common_objpfx}localedata GCONV_PATH=${common_objpfx}/iconvdata \
   LC_ALL=$l ${common_objpfx}elf/ld.so --library-path $common_objpfx \
   ${common_objpfx}localedata/xfrm-test $id < $cns.in \
   > ${common_objpfx}localedata/$cns.xout || status=1
  cmp -s $cns.in ${common_objpfx}localedata/$cns.xout || status=1
done

exit $status
# Local Variables:
#  mode:shell-script
# End:
