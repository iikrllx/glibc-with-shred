/* Support macros for making weak and strong aliases for symbols,
   and for using symbol sets and linker warnings with GNU ld.
   Copyright (C) 1995, 1996, 1997, 1998, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef _LIBC_SYMBOLS_H
#define _LIBC_SYMBOLS_H	1

/* This file's macros are included implicitly in the compilation of every
   file in the C library by -imacros.

   We include config.h which is generated by configure.
   It should define for us the following symbols:

   * HAVE_ASM_SET_DIRECTIVE if we have `.set B, A' instead of `A = B'.
   * ASM_GLOBAL_DIRECTIVE with `.globl' or `.global'.
   * HAVE_GNU_LD if using GNU ld, with support for weak symbols in a.out,
   and for symbol set and warning messages extensions in a.out and ELF.
   * HAVE_ELF if using ELF, which supports weak symbols using `.weak'.
   * HAVE_ASM_WEAK_DIRECTIVE if we have weak symbols using `.weak'.
   * HAVE_ASM_WEAKEXT_DIRECTIVE if we have weak symbols using `.weakext'.

   */

/* This is defined for the compilation of all C library code.  features.h
   tests this to avoid inclusion of stubs.h while compiling the library,
   before stubs.h has been generated.  Some library code that is shared
   with other packages also tests this symbol to see if it is being
   compiled as part of the C library.  We must define this before including
   config.h, because it makes some definitions conditional on whether libc
   itself is being compiled, or just some generator program.  */
#define _LIBC	1

/* Enable declarations of GNU extensions, since we are compiling them.  */
#define _GNU_SOURCE	1
/* And we also need the data for the reentrant functions.  */
#define _REENTRANT	1

#include <config.h>

/* The symbols in all the user (non-_) macros are C symbols.
   HAVE_GNU_LD without HAVE_ELF implies a.out.  */

#if defined HAVE_ASM_WEAK_DIRECTIVE || defined HAVE_ASM_WEAKEXT_DIRECTIVE
# define HAVE_WEAK_SYMBOLS
#endif

#ifndef __SYMBOL_PREFIX
# ifdef NO_UNDERSCORES
#  define __SYMBOL_PREFIX
# else
#  define __SYMBOL_PREFIX "_"
# endif
#endif

#ifndef C_SYMBOL_NAME
# ifdef NO_UNDERSCORES
#  define C_SYMBOL_NAME(name) name
# else
#  define C_SYMBOL_NAME(name) _##name
# endif
#endif

#ifndef __ASSEMBLER__
/* GCC understands weak symbols and aliases; use its interface where
   possible, instead of embedded assembly language.  */

/* Define ALIASNAME as a strong alias for NAME.  */
# define strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)));

/* This comes between the return type and function name in
   a function definition to make that definition weak.  */
# define weak_function __attribute__ ((weak))
# define weak_const_function __attribute__ ((weak, __const__))

# ifdef HAVE_WEAK_SYMBOLS

/* Define ALIASNAME as a weak alias for NAME.
   If weak aliases are not available, this defines a strong alias.  */
#  define weak_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));

/* Declare SYMBOL as weak undefined symbol (resolved to 0 if not defined).  */
#  define weak_extern(symbol) _weak_extern (symbol)
#  ifdef HAVE_ASM_WEAKEXT_DIRECTIVE
#   define _weak_extern(symbol) asm (".weakext " __SYMBOL_PREFIX #symbol);
#  else
#   define _weak_extern(symbol)    asm (".weak " __SYMBOL_PREFIX #symbol);
#  endif

# else

#  define weak_alias(name, aliasname) strong_alias(name, aliasname)
#  define weak_extern(symbol) /* Nothing. */

# endif

#else /* __ASSEMBLER__ */

# ifdef HAVE_ASM_SET_DIRECTIVE
#  define strong_alias(original, alias)		\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias);	\
  .set C_SYMBOL_NAME (alias),C_SYMBOL_NAME (original)
# else
#  define strong_alias(original, alias)		\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias);	\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)
# endif

# ifdef HAVE_WEAK_SYMBOLS
#  ifdef HAVE_ASM_WEAKEXT_DIRECTIVE
#   define weak_alias(original, alias)	\
  .weakext C_SYMBOL_NAME (alias), C_SYMBOL_NAME (original)
#   define weak_extern(symbol)	\
  .weakext C_SYMBOL_NAME (symbol)

#  else /* ! HAVE_ASM_WEAKEXT_DIRECTIVE */

#   define weak_alias(original, alias)	\
  .weak C_SYMBOL_NAME (alias);	\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)

#   define weak_extern(symbol)	\
  .weak C_SYMBOL_NAME (symbol)

#  endif /* ! HAVE_ASM_WEAKEXT_DIRECTIVE */

# else /* ! HAVE_WEAK_SYMBOLS */

#  define weak_alias(original, alias) strong_alias(original, alias)
#  define weak_extern(symbol) /* Nothing */
# endif /* ! HAVE_WEAK_SYMBOLS */

#endif /* __ASSEMBLER__ */

/* On some platforms we can make internal function calls (i.e., calls of
   functions not exported) a bit faster by using a different calling
   convention.  */
#ifndef internal_function
# define internal_function	/* empty */
#endif

/* Prepare for the case that `__builtin_expect' is not available.  */
#ifndef HAVE_BUILTIN_EXPECT
# define __builtin_expect(expr, val) (expr)
#endif

/* When a reference to SYMBOL is encountered, the linker will emit a
   warning message MSG.  */
#ifdef HAVE_GNU_LD
# ifdef HAVE_ELF

/* We want the .gnu.warning.SYMBOL section to be unallocated.  */
#  ifdef HAVE_ASM_PREVIOUS_DIRECTIVE
#   define __make_section_unallocated(section_string)	\
  asm(".section " section_string "; .previous");
#  elif defined HAVE_ASM_POPSECTION_DIRECTIVE
#   define __make_section_unallocated(section_string)	\
  asm(".pushsection " section_string "; .popsection");
#  else
#   define __make_section_unallocated(section_string)
#  endif

#  ifdef HAVE_SECTION_QUOTES
#   define link_warning(symbol, msg) \
  __make_section_unallocated (".gnu.warning." #symbol) \
  static const char __evoke_link_warning_##symbol[]	\
    __attribute__ ((section (".gnu.warning." #symbol "\"\n\t#\""))) = msg;
#  else
#   define link_warning(symbol, msg) \
  __make_section_unallocated (".gnu.warning." #symbol) \
  static const char __evoke_link_warning_##symbol[]	\
    __attribute__ ((section (".gnu.warning." #symbol "\n\t#"))) = msg;
#  endif
# else
#  define link_warning(symbol, msg)		\
  asm(".stabs \"" msg "\",30,0,0,0\n"	\
      ".stabs \"" __SYMBOL_PREFIX #symbol "\",1,0,0,0\n");
# endif
#else
/* We will never be heard; they will all die horribly.  */
# define link_warning(symbol, msg)
#endif

/* A canned warning for sysdeps/stub functions.  */
#define	stub_warning(name) \
  link_warning (name, \
		"warning: " #name " is not implemented and will always fail")

/*

*/

#ifdef HAVE_GNU_LD

/* Symbol set support macros.  */

# ifdef HAVE_ELF

/* Make SYMBOL, which is in the text segment, an element of SET.  */
#  define text_set_element(set, symbol)	_elf_set_element(set, symbol)
/* Make SYMBOL, which is in the data segment, an element of SET.  */
#  define data_set_element(set, symbol)	_elf_set_element(set, symbol)
/* Make SYMBOL, which is in the bss segment, an element of SET.  */
#  define bss_set_element(set, symbol)	_elf_set_element(set, symbol)

/* These are all done the same way in ELF.
   There is a new section created for each set.  */
#  ifdef SHARED
/* When building a shared library, make the set section writable,
   because it will need to be relocated at run time anyway.  */
#   define _elf_set_element(set, symbol) \
  static const void *__elf_set_##set##_element_##symbol##__ \
    __attribute__ ((unused, section (#set))) = &(symbol)
#  else
#   define _elf_set_element(set, symbol) \
  static const void *const __elf_set_##set##_element_##symbol##__ \
    __attribute__ ((unused, section (#set))) = &(symbol)
#  endif

/* Define SET as a symbol set.  This may be required (it is in a.out) to
   be able to use the set's contents.  */
#  define symbol_set_define(set)	symbol_set_declare(set)

/* Declare SET for use in this module, if defined in another module.  */
#  define symbol_set_declare(set) \
  extern void (*const __start_##set) (void) __attribute__ ((__weak__));	\
  extern void (*const __stop_##set) (void) __attribute__ ((__weak__));	\
  weak_extern (__start_##set) weak_extern (__stop_##set)

/* Return a pointer (void *const *) to the first element of SET.  */
#  define symbol_set_first_element(set)	(&__start_##set)

/* Return true iff PTR (a void *const *) has been incremented
   past the last element in SET.  */
#  define symbol_set_end_p(set, ptr)	((ptr) >= &__stop_##set)

# else	/* Not ELF: a.out.  */

#  define text_set_element(set, symbol)	\
  asm(".stabs \"" __SYMBOL_PREFIX #set "\",23,0,0," __SYMBOL_PREFIX #symbol)
#  define data_set_element(set, symbol)	\
  asm(".stabs \"" __SYMBOL_PREFIX #set "\",25,0,0," __SYMBOL_PREFIX #symbol)
#  define bss_set_element(set, symbol)	?error Must use initialized data.
#  define symbol_set_define(set)	void *const (set)[1];
#  define symbol_set_declare(set)	extern void (*const (set)[1]) (void);

#  define symbol_set_first_element(set)	&(set)[1]
#  define symbol_set_end_p(set, ptr)	(*(ptr) == 0)

# endif	/* ELF.  */
#endif	/* Have GNU ld.  */

#if DO_VERSIONING
# define symbol_version(real, name, version) \
     _symbol_version(real, name, version)
# define default_symbol_version(real, name, version) \
     _default_symbol_version(real, name, version)
# ifdef __ASSEMBLER__
#  define _symbol_version(real, name, version) \
     .symver real, name##@##version
#  define _default_symbol_version(real, name, version) \
     .symver real, name##@##@##version
# else
#  define _symbol_version(real, name, version) \
     __asm__ (".symver " #real "," #name "@" #version)
#  define _default_symbol_version(real, name, version) \
     __asm__ (".symver " #real "," #name "@@" #version)
# endif
#else
# define symbol_version(real, name, version)
# define default_symbol_version(real, name, version) \
  strong_alias(real, name)
#endif

#endif /* libc-symbols.h */
