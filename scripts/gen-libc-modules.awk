# Generate a header file that defines the MODULE_* macros for each library and
# module we build in glibc.  The library names are pulled in from soversions.i
# and the additional modules are passed in the BUILDLIST variable.
BEGIN {
  # BUILDLIST is set from the build-list variable in Makeconfig and is a space
  # separated list of non-library modules that we build in glibc.
  num = split (buildlist, libs, " ")
  # Separate the built modules from the libraries.
  libs[++num] = "LIBS_BEGIN"
}

# Skip over comments.
$1 == "#" {
  next
}

# We have only one special case in soversions.i parsing, which is to replace ld
# with rtld since that's what we call it throughout the sources.
match (FILENAME, ".*soversions.i") {
  name = $2
  if (name == "ld")
    name = "rtld"

  # Library names are not duplicated in soversions.i.
  libs[++num] = name
}

# Finally, print out the header file.
END {
  printf ("/* AUTOGENERATED BY gen-libc-modules.awk, DO NOT EDIT.  */\n\n")
  for (l in libs) {
    printf ("#define MODULE_%s %d\n", libs[l], l)
  }
}
