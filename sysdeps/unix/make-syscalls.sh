#! /bin/sh

# Usage: make-syscalls.sh ../sysdeps/unix/common
# Expects $sysdirs in environment.

##############################################################################
#
# This script is used to process the syscall data encoded in the various
# syscalls.list files to produce thin assembly syscall wrappers around the
# appropriate OS syscall. See syscall-template.s for more details on the
# actual wrapper.
#
# Syscall Signature Prefixes:
#
# C: cancellable (i.e., this syscall is a cancellation point)
# E: errno and return value are not set by the call
# V: errno is not set, but errno or zero (success) is returned from the call
#
# Syscall Signature Key Letters:
#
# a: unchecked address (e.g., 1st arg to mmap)
# b: non-NULL buffer (e.g., 2nd arg to read; return value from mmap)
# B: optionally-NULL buffer (e.g., 4th arg to getsockopt)
# f: buffer of 2 ints (e.g., 4th arg to socketpair)
# F: 3rd arg to fcntl
# i: scalar (any signedness & size: int, long, long long, enum, whatever)
# I: 3rd arg to ioctl
# n: scalar buffer length (e.g., 3rd arg to read)
# N: pointer to value/return scalar buffer length (e.g., 6th arg to recvfrom)
# p: non-NULL pointer to typed object (e.g., any non-void* arg)
# P: optionally-NULL pointer to typed object (e.g., 2nd argument to gettimeofday)
# s: non-NULL string (e.g., 1st arg to open)
# S: optionally-NULL string (e.g., 1st arg to acct)
# v: vararg scalar (e.g., optional 3rd arg to open)
# V: byte-per-page vector (3rd arg to mincore)
# W: wait status, optionally-NULL pointer to int (e.g., 2nd arg of wait4)
#

##############################################################################

thisdir=$1; shift

echo ''
echo \#### DIRECTORY = $thisdir
# Check each sysdep dir with higher priority than this one,
# and remove from $calls all the functions found in other dirs.
# Punt when we reach the directory defining these syscalls.
sysdirs=`for dir in $sysdirs; do
	 test $dir = $thisdir && break; echo $dir; done`
echo \#### SYSDIRS = $sysdirs

# Get the list of system calls for this directory.
calls=`sed 's/#.*$//
/^[ 	]*$/d' $thisdir/syscalls.list`

calls=`echo "$calls" |
while read file caller rest; do
  # Remove each syscall that is implemented by a file in $dir.
  # If a syscall specified a "caller", then only compile that syscall
  # if the caller function is also implemented in this directory.
  srcfile=-;
  for dir in $sysdirs; do
     { test -f $dir/$file.c && srcfile=$dir/$file.c; } ||
     { test -f $dir/$file.S && srcfile=$dir/$file.S; } ||
     { test x$caller != x- &&
	{ { test -f $dir/$caller.c && srcfile=$dir/$caller.c; } ||
	  { test -f $dir/$caller.S && srcfile=$dir/$caller.S; }; }; } && break;
  done;
  echo $file $srcfile $caller $rest;
done`

# Any calls left?
test -n "$calls" || exit 0

# This uses variables $weak, $strong, and $any_versioned.
emit_weak_aliases()
{
  # A shortcoming in the current gas is that it will only allow one
  # version-alias per symbol.  So we create new strong aliases as needed.
  vcount=""

  # We use the <shlib-compat.h> macros to generate the versioned aliases
  # so that the version sets can be mapped to the configuration's
  # minimum version set as per shlib-versions DEFAULT lines.  But note
  # we don't generate any "#if SHLIB_COMPAT (...)" conditionals.  To do
  # that we'd need to change the syscalls.list format so that it can
  # list the "obsoleted" version set too.  If it ever arises that we
  # have a syscall entry point that is obsoleted by a newer version set,
  # we'll have to revamp all this.
  if [ $any_versioned = t ]; then
    echo "	 echo '#include <shlib-compat.h>'; \\"
  fi

  for name in $weak; do
    case $name in
      *@@*)
	base=`echo $name | sed 's/@@.*//'`
	ver=`echo $name | sed 's/.*@@//;s/\./_/g'`
	echo "	 echo '#ifndef NOT_IN_libc'; \\"
	if test -z "$vcount" ; then
	  source=$strong
	  vcount=1
	else
	  source="${strong}_${vcount}"
	  vcount=`expr $vcount + 1`
	  echo "	 echo 'strong_alias ($strong, $source)'; \\"
	fi
	echo "	 echo 'versioned_symbol (libc, $source, $base, $ver)'; \\"
	echo "	 echo '#else'; \\"
	echo "	 echo 'strong_alias ($strong, $base)'; \\"
	echo "	 echo '#endif'; \\"
	;;
      *@*)
	base=`echo $name | sed 's/@.*//'`
	ver=`echo $name | sed 's/.*@//;s/\./_/g'`
	echo "	 echo '#ifndef NOT_IN_libc'; \\"
	if test -z "$vcount" ; then
	  source=$strong
	  vcount=1
	else
	  source="${strong}_${vcount}"
	  vcount=`expr $vcount + 1`
	  echo "	 echo 'strong_alias ($strong, $source)'; \\"
	fi
	echo "	 echo 'compat_symbol (libc, $source, $base, $ver)'; \\"
	echo "	 echo '#endif'; \\"
	;;
      !*)
	name=`echo $name | sed 's/.//'`
	echo "	 echo 'strong_alias ($strong, $name)'; \\"
	echo "	 echo 'libc_hidden_def ($name)'; \\"
	;;
      *)
	echo "	 echo 'weak_alias ($strong, $name)'; \\"
	echo "	 echo 'libc_hidden_weak ($name)'; \\"
	;;
    esac
  done
}


# Emit rules to compile the syscalls remaining in $calls.
echo "$calls" |
while read file srcfile caller syscall args strong weak; do

  vdso_syscall=
  case x"$syscall" in
  *:*@*)
    vdso_syscall="${syscall#*:}"
    syscall="${syscall%:*}"
    ;;
  esac

  case x"$syscall" in
  x-) callnum=_ ;;
  *)
  # Figure out if $syscall is defined with a number in syscall.h.
  callnum=-
  eval `{ echo "#include <sysdep.h>";
	echo "callnum=SYS_ify ($syscall)"; } |
	  $asm_CPP -D__OPTIMIZE__ - |
	  sed -n -e "/^callnum=.*$syscall/d" \
		 -e "/^\(callnum=\)[ 	]*\(.*\)/s//\1'\2'/p"`
  ;;
  esac

  cancellable=0
  noerrno=0
  errval=0
  case $args in
  C*) cancellable=1; args=`echo $args | sed 's/C:\?//'`;;
  E*) noerrno=1; args=`echo $args | sed 's/E:\?//'`;;
  V*) errval=1; args=`echo $args | sed 's/V:\?//'`;;
  esac

  # Derive the number of arguments from the argument signature
  case $args in
  [0-9]) nargs=$args;;
  ?:) nargs=0;;
  ?:?) nargs=1;;
  ?:??) nargs=2;;
  ?:???) nargs=3;;
  ?:????) nargs=4;;
  ?:?????) nargs=5;;
  ?:??????) nargs=6;;
  ?:???????) nargs=7;;
  ?:????????) nargs=8;;
  ?:?????????) nargs=9;;
  esac

  # Make sure only the first syscall rule is used, if multiple dirs
  # define the same syscall.
  echo ''
  echo "#### CALL=$file NUMBER=$callnum ARGS=$args SOURCE=$srcfile"

  # If there are versioned aliases the entry is only generated for the
  # shared library, unless it is a default version.
  any_versioned=f
  shared_only=f
  case $weak in
    *@@*) any_versioned=t ;;
    *@*) any_versioned=t shared_only=t ;;
  esac

 case x$srcfile"$callnum" in
 x--)
  # Undefined callnum for an extra syscall.
  if [ x$caller != x- ]; then
    if [ $noerrno != 0 ]; then
      echo >&2 "$0: no number for $fileno, no-error syscall ($strong $weak)"
      exit 2
    fi
    echo "unix-stub-syscalls += $strong $weak"
  fi
  ;;
 x*-) ;; ### Do nothing for undefined callnum
 x-*)
  echo "ifeq (,\$(filter $file,\$(unix-syscalls)))"

  if test $shared_only = t; then
    # The versioned symbols are only in the shared library.
    echo "ifneq (,\$(filter .os,\$(object-suffixes)))"
  fi
  # Accumulate the list of syscall files for this directory.
  echo "unix-syscalls += $file"
  test x$caller = x- || echo "unix-extra-syscalls += $file"

  # Emit a compilation rule for this syscall.
  if test $shared_only = t; then
    # The versioned symbols are only in the shared library.
    echo "shared-only-routines += $file"
    test -n "$vdso_syscall" || echo "\$(objpfx)${file}.os: \\"
  else
    object_suffixes='$(object-suffixes)'
    test -z "$vdso_syscall" || object_suffixes='$(object-suffixes-noshared)'
    echo "\
\$(foreach p,\$(sysd-rules-targets),\
\$(foreach o,${object_suffixes},\$(objpfx)\$(patsubst %,\$p,$file)\$o)): \\"
  fi

  echo "		\$(..)sysdeps/unix/make-syscalls.sh"
  case x"$callnum" in
  x_)
  echo "\
	\$(make-target-directory)
	(echo '/* Dummy module requested by syscalls.list */'; \\"
  ;;
  x*)
  echo "\
	\$(make-target-directory)
	(echo '#define SYSCALL_NAME $syscall'; \\
	 echo '#define SYSCALL_NARGS $nargs'; \\
	 echo '#define SYSCALL_SYMBOL $strong'; \\"
  [ $cancellable = 0 ] || echo "\
	 echo '#define SYSCALL_CANCELLABLE 1'; \\"
  [ $noerrno = 0 ] || echo "\
	 echo '#define SYSCALL_NOERRNO 1'; \\"
  [ $errval = 0 ] || echo "\
	 echo '#define SYSCALL_ERRVAL 1'; \\"
  echo "\
	 echo '#include <syscall-template.S>'; \\"
  ;;
  esac

  # Append any weak aliases or versions defined for this syscall function.
  emit_weak_aliases

  # And finally, pipe this all into the compiler.
  echo '	) | $(compile-syscall) '"\
\$(foreach p,\$(patsubst %$file,%,\$(basename \$(@F))),\$(\$(p)CPPFLAGS))"

  if test -n "$vdso_syscall"; then
    # In the shared library, we're going to emit an IFUNC using a vDSO function.
    # $vdso_syscall looks like "name@KERNEL_X.Y" where "name" is the symbol
    # name in the vDSO and KERNEL_X.Y is its symbol version.
    vdso_symbol="${vdso_syscall%@*}"
    vdso_symver="${vdso_syscall#*@}"
    vdso_symver="${vdso_symver//./_}"
    echo "\
\$(foreach p,\$(sysd-rules-targets),\$(objpfx)\$(patsubst %,\$p,$file).os): \\
		\$(..)sysdeps/unix/make-syscalls.sh\
	\$(make-target-directory)
	(echo '#include <dl-vdso.h>'; \\
	 echo 'extern void *${strong}_ifunc (void) __asm (\"${strong}\");'; \\
	 echo 'void *'; \\
	 echo '${strong}_ifunc (void)'; \\
	 echo '{'; \\
	 echo '  PREPARE_VERSION_KNOWN (symver, ${vdso_symver});'; \\
	 echo '  return _dl_vdso_vsym (\"${vdso_symbol}\", &symver);'; \\
	 echo '}'; \\
	 echo 'asm (\".type ${strong}, %gnu_indirect_function\");'; \\"
    # This is doing "libc_hidden_def (${strong})", but the compiler
    # doesn't know that we've defined ${strong} in the same file, so
    # we can't do it the normal way.
    echo "\
	 echo 'asm (\".globl __GI_${strong}\\n\"'; \\
	 echo '     \"__GI_${strong} = ${strong}\");'; \\"
    emit_weak_aliases
    echo '	) | $(compile-stdin.c) '"\
\$(foreach p,\$(patsubst %$file,%,\$(basename \$(@F))),\$(\$(p)CPPFLAGS))"
  fi

  if test $shared_only = t; then
    # The versioned symbols are only in the shared library.
    echo endif
  fi

  echo endif
 ;;
 esac

done
