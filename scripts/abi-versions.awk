# Script to generate <abi-versions.h> header file from Versions.all list.
# See include/shlib-compat.h comments for explanation.

# This script expects the following variables to be defined:
# oldest_abi		the oldest ABI supported

BEGIN {
  print "/* This file is automatically generated by abi-versions.awk.";
  print "   It defines symbols used by shlib-compat.h, which see.  */";
  print "\n#ifndef _ABI_VERSIONS_H\n#define _ABI_VERSIONS_H";
}

NF == 2 && $2 == "{" {
  thislib = $1;
  gsub(/[^A-Za-z0-9_ 	]/, "_"); libid = $1;
  printf "\n/* start %s */\n", thislib;
  n = 0;
  start = 0;
  next;
}
$1 == "}" {
  printf "/* end %s */\n", thislib;
  next;
}

$2 == "=" {
  old = $1; new = $3;
  gsub(/[^A-Za-z0-9_ 	]/, "_");
  oldid = $1; newid = $3;

  printf "#define ABI_%s_%s\tABI_%s_%s\n", libid, oldid, libid, newid;
  printf "#define VERSION_%s_%s\t%s\n", libid, oldid, new;
  next;
}

{
  vers = $1;
  gsub(/[^A-Za-z0-9_ 	]/, "_");
  versid = $1;

  printf "#define ABI_%s_%s\t%d\t/* support %s */\n", libid, versid, ++n, vers;
  printf "#define VERSION_%s_%s\t%s\n", libid, versid, vers;
  if ("GLIBC_" oldest_abi == vers)
    start = 1;
  if (start == 0 && oldest_abi != "default")
    --n;
  next;
}

END {
  print "\n#endif /* abi-versions.h */";
}
