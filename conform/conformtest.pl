#! /usr/bin/perl

$CC = "gcc";
$CFLAGS = "-I. '-D__attribute__(x)=' -D_XOPEN_SOURCE=500";

# List of the headers we are testing.
@headers = ("wordexp.h", "wctype.h", "wchar.h", "varargs.h", "utmpx.h",
	    "utime.h", "unistd.h", "ulimit.h", "ucontext.h", "time.h",
	    "termios.h", "tar.h", "sys/wait.h", "sys/uio.h", "sys/types.h",
	    "sys/times.h", "sys/timeb.h", "sys/time.h", "sys/statvfs.h",
	    "sys/stat.h", "sys/shm.h", "sys/sem.h", "sys/resource.h",
	    "sys/msg.h", "sys/mman.h", "sys/ipc.h", "syslog.h",
	    "stropts.h", "strings.h", "string.h", "stdlib.h", "stdio.h",
	    "stddef.h", "stdarg.h", "signal.h", "setjmp.h", "semaphore.h",
	    "search.h", "sched.h", "regex.h", "pwd.h", "pthread.h",
	    "poll.h", "nl_types.h", "ndbm.h", "mqueue.h", "monetary.h",
	    "math.h", "locale.h", "libgen.h", "langinfo.h", "iso646.h",
	    "inttypes.h", "iconv.h", "grp.h", "glob.h", "ftw.h", "fnmatch.h",
	    "fmtmsg.h", "float.h", "fcntl.h", "errno.h", "dlfcn.h", "dirent.h",
	    "ctype.h", "cpio.h", "assert.h", "aio.h");

# These are the ISO C99 keywords.
@keywords = ('auto', 'break', 'case', 'char', 'const', 'continue', 'default',
	     'do', 'double', 'else', 'enum', 'extern', 'float', 'for', 'goto',
	     'if', 'inline', 'int', 'long', 'register', 'restrict', 'return',
	     'short', 'signed', 'sizeof', 'static', 'struct', 'switch',
	     'typedef', 'union', 'unsigned', 'void', 'volatile', 'while');

# Some headers need a bit more attention.
$mustprepend{'regex.h'} = "#include <sys/types.h>\n";

# Make an hash table from this information.
while ($#keywords) {
  $iskeyword{pop (@keywords)} = 1;
}

$tmpdir = "/tmp";

$verbose = 1;

$total = 0;
$skipped = 0;
$errors = 0;

#$dialect = "ISO";
#$dialect = "POSIX";
#$dialect = "XPG3";
#$dialect = "XPG4";
$dialect = "UNIX98";


sub poorfnmatch {
  my($pattern, $string) = @_;
  my($strlen) = length ($string);
  my($res);

  if (substr ($pattern, 0, 1) eq '*') {
    my($patlen) = length ($pattern) - 1;
    $res = ($strlen >= $patlen
	    && substr ($pattern, -$patlen, $patlen) eq substr ($string, -$patlen, $patlen));
  } elsif (substr ($pattern, -1, 1) eq '*') {
    my($patlen) = length ($pattern) - 1;
    $res = ($strlen >= $patlen
	    && substr ($pattern, 0, $patlen) eq substr ($string, 0, $patlen));
  } else {
    $res = $pattern eq $string;
  }
  return $res;
}


sub compiletest
{
  my($fnamebase, $msg, $errmsg, $skip) = @_;
  my($result) = $skip;
  my($printlog) = 0;

  ++$total;
  printf ("  $msg...");

  if ($skip != 0) {
    ++$skipped;
    printf (" SKIP\n");
  } else {
    $ret = system "$CC $CFLAGS -c $fnamebase.c -o $fnamebase.o > $fnamebase.out 2>&1";
    if ($ret != 0) {
      printf (" FAIL\n");
      if ($verbose != 0) {
	printf ("    $errmsg  Compiler message:\n");
	$printlog = 1;
      }
      ++$errors;
      $result = 1;
    } else {
      printf (" OK\n");
      if ($verbose > 1 && -s "$fnamebase.out") {
	# We print all warnings issued.
	$printlog = 1;
      }
    }
    if ($printlog != 0) {
      printf ("    " . "-" x 71 . "\n");
      open (MESSAGE, "< $fnamebase.out");
      while (<MESSAGE>) {
	printf ("    %s", $_);
      }
      close (MESSAGE);
      printf ("    " . "-" x 71 . "\n");
    }
  }
  unlink "$fnamebase.c";
  unlink "$fnamebase.o";
  unlink "$fnamebase.out";

  $result;
}


sub runtest
{
  my($fnamebase, $msg, $errmsg, $skip) = @_;
  my($result) = $skip;
  my($printlog) = 0;

  ++$total;
  printf ("  $msg...");

  if ($skip != 0) {
    ++$skipped;
    printf (" SKIP\n");
  } else {
    $ret = system "$CC $CFLAGS -o $fnamebase $fnamebase.c > $fnamebase.out 2>&1";
    if ($ret != 0) {
      printf (" FAIL\n");
      if ($verbose != 0) {
	printf ("    $errmsg  Compiler message:\n");
	$printlog = 1;
      }
      ++$errors;
      $result = 1;
    } else {
      # Now run the program.  If the exit code is not zero something is wrong.
      $result = system "$fnamebase > $fnamebase.out2 2>&1";
      if ($result == 0) {
	printf (" OK\n");
	if ($verbose > 1 && -s "$fnamebase.out") {
	  # We print all warnings issued.
	  $printlog = 1;
	  system "cat $fnamebase.out2 >> $fnamebase.out";
	}
      } else {
	printf (" FAIL\n");
	$printlog = 1;
	unlink "$fnamebase.out";
	rename "$fnamebase.out2", "$fnamebase.out";
      }
    }
    if ($printlog != 0) {
      printf ("    " . "-" x 71 . "\n");
      open (MESSAGE, "< $fnamebase.out");
      while (<MESSAGE>) {
	printf ("    %s", $_);
      }
      close (MESSAGE);
      printf ("    " . "-" x 71 . "\n");
    }
  }
  unlink "$fnamebase";
  unlink "$fnamebase.c";
  unlink "$fnamebase.o";
  unlink "$fnamebase.out";
  unlink "$fnamebase.out2";

  $result;
}


sub newtoken {
  my($token, $nerrors, @allow) = @_;
  my($idx);

  if ($token =~ /^[0-9_]/ || $iskeyword{$token}) {
    return $nerrors;
  }

  for ($idx = 0; $idx <= $#allow; ++$idx) {
    if (poorfnmatch ($allow[$idx], $token)) {
      return $nerrors;
    }
  }

  ++$nerrors;
  if ($nerrors == 1) {
    printf ("FAIL\n    " . "-" x 72 . "\n");
  }
  printf ("    Namespace violation: \"%s\"\n", $token);
  return $nerrors;
}


sub checknamespace {
  my($h, $fnamebase, @allow) = @_;
  my($nerrors) = 0;

  ++$total;

  # Generate a program to get the contents of this header.
  open (TESTFILE, ">$fnamebase.c");
  print TESTFILE "#include <$h>\n";
  close (TESTFILE);

  open (CONTENT, "$CC $CFLAGS -E $fnamebase.c -Wp,-dN | sed -e '/^# [1-9]/d' -e '/^[[:space:]]*\$/d' |");
  while (<CONTENT>) {
    chop;
    if (/^#define (.*)/) {
      $nerrors = newtoken ($1, $nerrors, @allow);
    } else {
      # We have to tokenize the line.
      my($str) = $_;
      my($index) = 0;
      my($len) = length ($str);

      foreach $token (split(/[^a-zA-Z0-9_]/, $str)) {
	if ($token ne "") {
	  $nerrors = newtoken ($token, $nerrors, @allow);
	}
      }
    }
  }
  close (CONTENT);
  unlink "$fnamebase.c";
  if ($nerrors != 0) {
    printf ("    " . "-" x 72 . "\n");
    ++$errors;
  } else {
    printf ("OK\n");
  }
}


while ($#headers >= 0) {
  my($h) = pop (@headers);
  my($hf) = $h;
  $hf =~ s|/|-|;
  my($fnamebase) = "$tmpdir/$hf-test";
  my($missing);
  my(@allow) = ();
  my(@allowheader) = ();
  my($prepend) = $mustprepend{$h};

  printf ("Testing <$h>\n");
  printf ("----------" . "-" x length ($h) . "\n");

  # Generate a program to test for the availability of this header.
  open (TESTFILE, ">$fnamebase.c");
  print TESTFILE "$prepend";
  print TESTFILE "#include <$h>\n";
  close (TESTFILE);

  $missing = compiletest ($fnamebase, "Checking whether <$h> is available",
			  "Header <$h> not available", 0);

  printf ("\n");

  open (CONTROL, "$CC -E -D$dialect - < data/$h-data |");
  control: while (<CONTROL>) {
    chop;
    next control if (/^#/);
    next control if (/^[ 	]*$/);

    if (/^element *({([^}]*)}|([^ ]*)) *({([^}]*)}|([^ ]*)) *([A-Za-z0-9_]*) *(.*)/) {
      my($struct) = "$2$3";
      my($type) = "$5$6";
      my($member) = "$7";
      my($rest) = "$8";
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $member;

      # Generate a program to test for the availability of this member.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "$struct a;\n";
      print TESTFILE "$struct b;\n";
      print TESTFILE "extern void xyzzy (__typeof__ (&b.$member), __typeof__ (&a.$member), unsigned);\n";
      print TESTFILE "void foobarbaz (void) {\n";
      print TESTFILE "  xyzzy (&a.$member, &b.$member, sizeof (a.$member));\n";
      print TESTFILE "}\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Testing for member $member",
			  "Member \"$member\" not available.", $res);


      # Test the types of the members.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "$struct a;\n";
      print TESTFILE "extern $type b$rest;\n";
      print TESTFILE "extern __typeof__ (a.$member) b;\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Testing for type of member $member",
		   "Member \"$member\" does not have the correct type.", $res);
    } elsif (/^constant *([a-zA-Z0-9_]*) *([A-Za-z0-9_]*)?/) {
      my($const) = $1;
      my($value) = $2;
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $const;

      # Generate a program to test for the availability of this constant.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "__typeof__ ($const) a = $const;\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Testing for constant $const",
			  "Constant \"$const\" not available.", $res);

      if ($value ne "") {
	# Generate a program to test for the value of this constant.
	open (TESTFILE, ">$fnamebase.c");
	print TESTFILE "$prepend";
	print TESTFILE "#include <$h>\n";
	print TESTFILE "int main (void) { return $const != $value; }\n";
	close (TESTFILE);

	$res = runtest ($fnamebase, "Testing for value of constant $const",
			"Constant \"$const\" has not the right value.", $res);
      }
    } elsif (/^typed-constant *([a-zA-Z0-9_]*) *({([^}]*)}|([^ ]*)) *([A-Za-z0-9_]*)?/) {
      my($const) = $1;
      my($type) = "$3$4";
      my($value) = $5;
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $const;

      # Generate a program to test for the availability of this constant.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "__typeof__ ($const) a = $const;\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Testing for constant $const",
			  "Constant \"$const\" not available.", $res);

      # Test the types of the members.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "__typeof__ (($type) 0) a;\n";
      print TESTFILE "extern __typeof__ ($const) a;\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Testing for type of constant $const",
		   "Constant \"$const\" does not have the correct type.",
		   $res);

      if ($value ne "") {
	# Generate a program to test for the value of this constant.
	open (TESTFILE, ">$fnamebase.c");
	print TESTFILE "$prepend";
	print TESTFILE "#include <$h>\n";
	print TESTFILE "int main (void) { return $const != $value; }\n";
	close (TESTFILE);

	$res = runtest ($fnamebase, "Testing for value of constant $const",
			"Constant \"$const\" has not the right value.", $res);
      }
    } elsif (/^type *({([^}]*)|([a-zA-Z0-9_]*))/) {
      my($type) = "$2$3";

      # Remember that this name is allowed.
      if ($type =~ /^struct *(.*)/) {
	push @allow, $1;
      } elsif ($type =~ /^union *(.*)/) {
	push @allow, $1;
      } else {
	push @allow, $type;
      }

      # Remember that this name is allowed.
      push @allow, $type;

      # Generate a program to test for the availability of this constant.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "$type *a;\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Testing for type $type",
		   "Type \"$type\" not available.", $missing);
    } elsif (/^function *({([^}]*)}|([a-zA-Z0-9_]*)) [(][*]([a-zA-Z0-9_]*) ([(].*[)])/) {
      my($rettype) = "$2$3";
      my($fname) = "$4";
      my($args) = "$5";
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $fname;

      # Generate a program to test for availability of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      # print TESTFILE "#undef $fname\n";
      print TESTFILE "$rettype (*(*foobarbaz) $args = $fname;\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Test availability of function $fname",
			  "Function \"$fname\" is not available.", $res);

      # Generate a program to test for the type of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      # print TESTFILE "#undef $fname\n";
      print TESTFILE "extern $rettype (*(*foobarbaz) $args;\n";
      print TESTFILE "extern __typeof__ (&$fname) foobarbaz;\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Test for type of function $fname",
		   "Function \"$fname\" has incorrect type.", $res);
    } elsif (/^function *({([^}]*)}|([a-zA-Z0-9_]*)) ([a-zA-Z0-9_]*) ([(].*[)])/) {
      my($rettype) = "$2$3";
      my($fname) = "$4";
      my($args) = "$5";
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $fname;

      # Generate a program to test for availability of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      # print TESTFILE "#undef $fname\n";
      print TESTFILE "$rettype (*foobarbaz) $args = $fname;\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Test availability of function $fname",
			  "Function \"$fname\" is not available.", $res);

      # Generate a program to test for the type of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      # print TESTFILE "#undef $fname\n";
      print TESTFILE "extern $rettype (*foobarbaz) $args;\n";
      print TESTFILE "extern __typeof__ (&$fname) foobarbaz;\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Test for type of function $fname",
		   "Function \"$fname\" has incorrect type.", $res);
    } elsif (/^variable *({([^}]*)}|([a-zA-Z0-9_]*)) ([a-zA-Z0-9_]*)/) {
      my($type) = "$2$3";
      my($vname) = "$4";
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $vname;

      # Generate a program to test for availability of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      # print TESTFILE "#undef $fname\n";
      print TESTFILE "$type *foobarbaz = &$vname;\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Test availability of variable $vname",
			  "Variable \"$vname\" is not available.", $res);

      # Generate a program to test for the type of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      # print TESTFILE "#undef $fname\n";
      print TESTFILE "extern $type $vname;\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Test for type of variable $fname",
		   "Variable \"$vname\" has incorrect type.", $res);
    } elsif (/^macro-function *({([^}]*)}|([a-zA-Z0-9_]*)) ([a-zA-Z0-9_]*) ([(].*[)])/) {
      my($rettype) = "$2$3";
      my($fname) = "$4";
      my($args) = "$5";
      my($res) = $missing;

      # Remember that this name is allowed.
      push @allow, $fname;

      # Generate a program to test for availability of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "#ifndef $fname\n";
      print TESTFILE "$rettype (*foobarbaz) $args = $fname;\n";
      print TESTFILE "#endif\n";
      close (TESTFILE);

      $res = compiletest ($fnamebase, "Test availability of function $fname",
			  "Function \"$fname\" is not available.", $res);

      # Generate a program to test for the type of this function.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "#ifndef $fname\n";
      print TESTFILE "extern $rettype (*foobarbaz) $args;\n";
      print TESTFILE "extern __typeof__ (&$fname) foobarbaz;\n";
      print TESTFILE "#endif\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Test for type of function $fname",
		   "Function \"$fname\" has incorrect type.", $res);
    } elsif (/^macro *([^ 	]*)/) {
      my($macro) = "$1";

      # Remember that this name is allowed.
      push @allow, $macro;

      # Generate a program to test for availability of this macro.
      open (TESTFILE, ">$fnamebase.c");
      print TESTFILE "$prepend";
      print TESTFILE "#include <$h>\n";
      print TESTFILE "#ifndef $macro\n";
      print TESTFILE "# error \"Macro $macro not defined\"\n";
      print TESTFILE "#endif\n";
      close (TESTFILE);

      compiletest ($fnamebase, "Test availability of macro $macro",
		   "Macro \"$macro\" is not available.", $missing);
    } elsif (/^allow *(.*)/) {
      my($pattern) = $1;
      push @allow, $pattern;
      next control;
    } elsif (/^allow-header *(.*)/) {
      my($pattern) = $1;
      push @allowheader, $pattern;
      next control;
    } else {
      # printf ("line is `%s'\n", $_);
      next control;
    }

    printf ("\n");
  }
  close (CONTROL);

  # Read the data files for the header files which are allowed to be included.
  while ($#allowheader >= 0) {
    my($ah) = pop @allowheader;

    open (ALLOW, "$CC -E -D$dialect - < data/$ah-data |");
    acontrol: while (<ALLOW>) {
      next acontrol if (/^#/);
      next acontrol if (/^[ 	]*$/);

      if (/^element *({([^}]*)}|([^ ]*)) *({([^}]*)}|([^ ]*)) *([A-Za-z0-9_]*) *(.*)/) {
	push @allow, $7;
      } elsif (/^constant *([a-zA-Z0-9_]*) *([A-Za-z0-9_]*)?/) {
	push @allow, $1;
      } elsif (/^typed-constant *([a-zA-Z0-9_]*) *({([^}]*)}|([^ ]*)) *([A-Za-z0-9_]*)?/) {
	push @allow, 1;
      } elsif (/^type *({([^}]*)|([a-zA-Z0-9_]*))/) {
	my($type) = "$2$3";

	# Remember that this name is allowed.
	if ($type =~ /^struct *(.*)/) {
	  push @allow, $1;
	} elsif ($type =~ /^union *(.*)/) {
	  push @allow, $1;
	} else {
	  push @allow, $type;
	}
      } elsif (/^function *({([^}]*)}|([a-zA-Z0-9_]*)) [(][*]([a-zA-Z0-9_]*) ([(].*[)])/) {
	push @allow, $4;
      } elsif (/^function *({([^}]*)}|([a-zA-Z0-9_]*)) ([a-zA-Z0-9_]*) ([(].*[)])/) {
	push @allow, $4;
      } elsif (/^variable *({([^}]*)}|([a-zA-Z0-9_]*)) ([a-zA-Z0-9_]*)/) {
	push @allow, $4;
      } elsif (/^macro-function *({([^}]*)}|([a-zA-Z0-9_]*)) ([a-zA-Z0-9_]*) ([(].*[)])/) {
	push @allow, $4;
      } elsif (/^macro *([^ 	]*)/) {
	push @allow, $1;
      } elsif (/^allow *(.*)/) {
	push @allow, $1;
      } elsif (/^allow-header *(.*)/) {
	push @allowheader, $1;
      }
    }
    close (ALLOW);
  }

  # Now check the namespace.
  printf ("  Checking the namespace of \"%s\"... ", $h);
  if ($missing) {
    ++$skipped;
    printf ("SKIP\n");
  } else {
    checknamespace ($h, $fnamebase, @allow);
  }

  printf ("\n\n");
}

printf "-" x 76 . "\n";
printf ("  Total number of tests  : %4d\n", $total);
printf ("  Number of failed tests : %4d (%3d%%)\n", $errors, ($errors * 100) / $total);
printf ("  Number of skipped tests: %4d (%3d%%)\n", $skipped, ($skipped * 100) / $total);

exit $errors != 0;
