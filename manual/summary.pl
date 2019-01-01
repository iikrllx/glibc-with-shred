#!/usr/bin/perl
# Generate the Summary of Library Facilities (summary.texi).

# Copyright (C) 2017-2019 Free Software Foundation, Inc.
# This file is part of the GNU C Library.
# Contributed by Rical Jasan <ricaljasan@pacific.net>, 2017.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, see
# <http://www.gnu.org/licenses/>.

# Anything declared in a header or defined in a standard should have
# its origins annotated using the @standards macro (see macro.texi).
# This script checks all such elements in the manual (generally,
# @def|item*-commands), ensuring annotations are present and correct.
# If any errors are detected, they are all reported at the end and
# failure is indicated.

use strict;
use warnings;
use locale;
use File::Basename;

$| = 1;
my $script = basename $0;

&help if $ARGV[0] eq "--help"; # Will exit(0).

my @texis = @ARGV;

# Various regexes.
my $nde = qr/^\@node /;
my $def = qr/^\@def/;
my $itm = qr/^\@item /;
my $itms = qr/^\@itemx? /; # Don't match @itemize.
my $ann = qr/^\@(def\w+|item)x? /; # Annotatable.
my $std = qr/^\@standards\{/;
my $stx = qr/^\@standardsx\{/;
my $stds = qr/^\@standardsx?\{/;
my $strict_std = qr/^\@standards\{([^,]+, )[^,\}]+\}$/;
my $strict_stx = qr/^\@standardsx\{([^,]+, ){2}[^,\}]+\}$/;
my $lcon = qr/([vf]?table|itemize|enumerate)/;
my $list = qr/^\@${lcon}/;
my $endl = qr/^\@end ${lcon}/;
my $ign = qr/^\@ignore/;
my $eig = qr/^\@end ignore/;

# Global scope.
my $node;
our $texi;
my $input;
my %entries;
my %errors;

for $texi (@texis) {
    open $input, '<', $texi or die "open $texi: $!";
    while (my $line = <$input>) {
	if ($line =~ $nde) {
	    $node = &get_node($line);
	} elsif ($line =~ $def) {
	    &process_annotation($line);
	} elsif ($line =~ $list) {
	    &process_list($1); # @items occur in list or table context.
	} elsif ($line =~ $stds) {
	    &record_error("Misplaced annotation", ["[$.] ".$line]);
	} elsif ($line =~ $ign) {
	    while (<$input> !~ $eig) {}
	}
    }
    close $input or die "close $texi: $!";
}

# Disabled until annotations are complete.
&print_errors() if %errors && 0; # Will exit(1).

print("\@c DO NOT EDIT THIS FILE!\n".
      "\@c This file is generated by $script from the Texinfo sources.\n".
      "\@c The \@items are \@include'd from a \@table in header.texi.\n\n");

&print_entry($_) for sort keys %entries;

# Processes an annotatable element, including any subsequent elements
# in an @*x chain, ensuring @standards are present, with valid syntax,
# either recording any errors detected or creating Summary entries.
# This function is the heart of the script.
#
# Prototypes and standards are gathered into separate lists and used
# to evaluate the completeness and correctness of annotations before
# generating the Summary entries.  "Prototype" is used to refer to an
# element's entire definition while avoiding conflation with
# @def*-commands.  "Element" is strictly used here to refer to the
# name extracted from the prototype, as used in @standardsx, for
# sorting the Summary.
sub process_annotation
{
    my $line = shift;
    my (@prototypes, @standards, $i, @tmp);

    # Gather prototypes and standards.
    push @prototypes, $line;
    while ($line = <$input>) {
	last if $line !~ $ann;
	push @prototypes, $line;
    }
    if ($line !~ $stds) { # The fundamental error.
	return &record_error('Missing annotation', \@prototypes);
    }
    push @standards, $line;
    push @standards, $line while ($line = <$input>) =~ $stds;

    # If next line is an @item, seek back to catch it on the next
    # iteration.  This avoids imposing a non-Texinfo syntax
    # requirement of blank lines between consecutive annotated @items.
    if ($line =~ $itm) {
	seek $input, -length($line), 1 or die "seek: $!";
    }

    # Strict check for syntax errors.  Other matches are loose, which
    # aids error detection and reporting by ensuring things that look
    # like standards aren't simply passed over, but caught here.
    for ($i=0; $i<@standards; ++$i) {
	my $standard = $standards[$i];
	if ($standard !~ $strict_std && $standard !~ $strict_stx) {
	    push @tmp, $standard;
	}
    }
    return &record_error('Invalid syntax', \@tmp) if @tmp;

    # @standardsx should not be in non-@*x chains.
    if (@prototypes == 1) {
	for ($i=0; $i<@standards; ++$i) {
	    return &record_error('Misplaced @standardsx', \@prototypes)
		if $standards[$i] =~ $stx;
	}
    }
    # @standards may only occur once in @*x chains, at the beginning.
    if (@prototypes > 1) {
	for ($i=1; $i<@standards; ++$i) {
	    return &record_error('Misplaced @standards', \@prototypes)
		if $standards[$i] =~ $std;
	}
    }

    # The @standards are aligned.
    &add_entries(\@prototypes, \@standards);
}

# Goes through the prototypes, cleaning them up and extracting the
# elements, pairing them with the appropriate annotations to create
# Summary entries.
sub add_entries
{
    my ($prototypes, $standards) = @_;
    my $isx = @{$prototypes} > 1 ? 1 : 0;
    my $allx = $standards->[0] =~ $stx ? 1 : 0;
    my ($defstd, $defhdr, %standardsx, $i, $j);

    # Grab the default annotation and index any @standardsx.  Take
    # care in case there is no default.
    if ($isx) {
	if (!$allx) {
	    ($defstd, $defhdr)
		= $standards->[0] =~ /${std}([^,]+), (.*)\}$/;
	}
	for ($i = $allx ? 0 : 1; $i<@{$standards}; ++$i) {
	    my ($e, $s, $h)
		= $standards->[$i] =~ /${stx}([^,]+), ([^,]+), (.*)\}$/;
	    push @{$standardsx{$e}{hs}}, [$h, $s];
	}
    }

    for ($i=0; $i<@{$prototypes}; ++$i) {
	my $e = &get_element($prototypes->[$i]);
	my $p = &get_prototype($prototypes->[$i]);
	my ($s, $h);
	if ($isx && exists $standardsx{$e}) {
	    for ($j=0; $j<@{$standardsx{$e}{hs}}; ++$j) {
		$h = $standardsx{$e}{hs}[$j]->[0];
		$s = $standardsx{$e}{hs}[$j]->[1];
		&record_entry($e, $p, $h, $s, $node);
		++$standardsx{$e}{seen};
	    }
	} elsif ($isx && $allx) {
	    &record_error('Missing annotation', [$prototypes->[$i]]);
	} elsif ($isx) {
	    &record_entry($e, $p, $defhdr, $defstd, $node);
	} else {
	    for ($j=0; $j<@{$standards}; ++$j) {
		($s, $h) = $standards->[$j] =~ /${std}([^,]+), ([^,\}]+)\}$/;
		&record_entry($e, $p, $h, $s, $node);
	    }
	}
    }

    # Check if there were any unmatched @standardsx.
    for my $e (keys %standardsx) {
	if (!exists $standardsx{$e}{seen}) {
	    &record_error('Spurious @standardsx', [$e."\n"])
	}
    }
}

# Stores a Summary entry in %entries.  May be called multiple times
# per element if multiple header and standard annotations exist.  Also
# keys on prototypes, as some elements have multiple prototypes.  See
# isnan in arith.texi for one example.
sub record_entry
{
    my ($ele, $proto, $hdr, $std, $node) = @_;
    push @{$entries{$ele}{$proto}}, [$hdr, $std, $node];
}

# Processes list or table contexts, with nesting.
sub process_list
{
    my $type = shift;
    my $in_vtbl = $type eq "vtable" ? 1 : 0;

    while (my $line = <$input>) {
	if ($line =~ $itms) {
	    next if ! $in_vtbl; # Not an annotatable context.
	    &process_annotation($line);
	} elsif ($line =~ $def) {
	    &process_annotation($line);
	} elsif ($line =~ $stds) {
	    &record_error('Misplaced annotation', ["[$.] ".$line]);
	} elsif ($line =~ $endl) {
	    return; # All done.
	} elsif ($line =~ $list) {
	    &process_list($1); # Nested list.
	}
    }
}

# Returns the current node from an @node line.  Used for referencing
# from the Summary.
sub get_node
{
    my $line = shift;
    chomp $line;
    $line =~ s/$nde//;
    my ($n) = split ',', $line;
    return $n
}

# Returns the cleaned up prototype from @def|item* lines.
sub get_prototype
{
    my $dfn = shift;
    chomp $dfn;
    $dfn =~ s/\s+/ /g; # Collapse whitespace.
    $dfn =~ s/ \{([^\}]*)\} / $1 /g; # Remove grouping braces.
    $dfn =~ s/^\@\S+ //; # Remove @-command.
    $dfn =~ s/^Macro //i; # Scrape off cruft...
    $dfn =~ s/^Data Type //i;
    $dfn =~ s/^Variable //i;
    $dfn =~ s/^Deprecated Function //i;
    $dfn =~ s/^SVID Macro //i;
    $dfn =~ s/^Obsolete function //i;
    $dfn =~ s/^Constant //i;
    $dfn =~ s/^Type //i;
    $dfn =~ s/^Function //i;
    $dfn =~ s/^\{(.*)\}$/$1/; # Debrace yourself.
    $dfn =~ s/^\{([^\}]*)\} /$1 /; # These ones too.
    return $dfn;
}

# Returns an annotated element's name.
#
# Takes a line defining an annotatable element (e.g., @def|item*),
# splitting it on whitespace.  The element is generally detected as
# the member immediately preceding the first parenthesized expression
# (e.g., a function), or the last token in the list.  Some additional
# cleanup is applied to the element before returning it.
sub get_element
{
    my $i = 0;
    my @toks = split /\s+/, shift;
    # tzname array uses '['; don't match function pointers.
    ++$i while $toks[$i] && $toks[$i] !~ /^[\(\[](?!\*)/;
    $toks[$i-1] =~ s/^\*//; # Strip pointer type syntax.
    $toks[$i-1] =~ s/^\{?([^\}]+)\}?$/$1/; # Strip braces.
    $toks[$i-1] =~ s/^\(\*([^\)]+)\)$/$1/; # Function pointers.
    return $toks[$i-1];
}

# Records syntax errors detected in the manual related to @standards.
# The @def|item*s are grouped by file, then errors, to make it easier
# to track down exactly where and what the problems are.
sub record_error
{
    my ($err, $list) = @_;
    push @{$errors{$texi}{$err}}, $_ for (@{$list});
    return 0;
}

# Reports all detected errors and exits with failure.  Indentation is
# used for readability, and "ERROR" is used for visibility.
sub print_errors
{
    for $texi (sort keys %errors) {
	print STDERR "ERRORS in $texi:\n";
	for my $err (sort keys %{$errors{$texi}}) {
	    print STDERR "  $err:\n";
	    print STDERR "    $_" for (@{$errors{$texi}{$err}});
	}
    }
    print(STDERR "\nFor a description of expected syntax, see ".
	  "\`$script --help'\n\n");
    exit 1;
}

# Prints an entry in the Summary.
#
# All the blank lines in summary.texi may seem strange at first, but
# they have significant impact on how Texinfo renders the output.
# Essentially, each line is its own paragraph.  There is a @comment
# with the element name, arguably unnecessary, but useful for seeing
# the sorting order and extracted element names, and maintains the
# format established by summary.awk.  Each @item in the @table is the
# prototype, which may be anything from just a variable name to a
# function declaration.  The body of each @item contains lines
# annotating the headers and standards each element is declared
# in/comes from, with a reference to the @node documenting the element
# wrt. each header and standard combination.
sub print_entry
{
    my $element = shift;
    for my $prototype (sort keys %{$entries{$element}}) {
	print "\@comment $element\n\@item $prototype\n\n";
	for (@{$entries{$element}{$prototype}}) {
	    my ($header, $standard, $node)
		= ($_->[0], $_->[1], $_->[2]);
	    if ($header =~ /^\(none\)$/i) {
		$header = "\@emph{no header}";
	    } elsif ($header =~ /\(optional\)$/) {
		$header =~ s/^(\S+) \((.*)\)$/\@file{$1} \@emph{$2}/;
	    } elsif ($header ne '???') {
		$header = "\@file{$header}";
	    }
	    print "$header ($standard):  \@ref{$node}.\n\n";
	}
    }
}

# Document the syntax of @standards.
sub help
{
    print "$script ";
    print <<'EOH';
generates the Summary of Library Facilities (summary.texi)
from @standards and @standardsx macros in the Texinfo sources (see
macros.texi).  While generating the Summary, it also checks that
@standards are used, correctly.

In general, any @def*-command or @item in a @vtable is considered
annotatable.  "Misplaced annotation" refers to @standards macros
detected outside an annotatable context.  "Missing annotation" refers
to annotatable elements without @standards.  @standards are expected
to immediately follow the elements being annotated.  In @*x lists,
@standards sets the default annotation and may only occur as the first
annotation ("Misplaced @standards").  @standardsx may not be used
outside @*x lists ("Misplaced @standardsx").  "Spurious @standardsx"
refers to otherwise valid @standardsx macros that were not matched to
an element in an @*x list.  "Invalid syntax" means just that.

The syntax of @standards annotations is designed to accomodate
multiple header and standards annotations, as necessary.

Examples:

  @deftp FOO
  @standards{STD, HDR}

  @defvar BAR
  @standards{STD, HDR1}
  @standards{STD, HDR2}

  @deftypefun foo
  @deftypefunx fool
  @standards{STD, HDR}

  @item bar
  @itemx baz
  @standardsx{bar, STD1, HDR1}
  @standardsx{baz, STD1, HDR1}
  @standardsx{baz, STD2, HDR2}

Note that @standardsx deviates from the usual Texinfo syntax in that
it is optional and may be used without @standards.
EOH
    ; exit 0;
}
