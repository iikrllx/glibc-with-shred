/* Support macros for making weak and strong aliases for symbols,
   and for using symbol sets and linker warnings with GNU ld.
   Copyright (C) 1995-1998,2000,2001,2002,2003 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef _LIBC_SYMBOLS_H
#define _LIBC_SYMBOLS_H	1

/* This file's macros are included implicitly in the compilation of every
   file in the C library by -imacros.

   We include config.h which is generated by configure.
   It should define for us the following symbols:

   * HAVE_ASM_SET_DIRECTIVE if we have `.set B, A' instead of `A = B'.
   * ASM_GLOBAL_DIRECTIVE with `.globl' or `.global'.
   * ASM_TYPE_DIRECTIVE_PREFIX with `@' or `#' or whatever for .type,
     or leave it undefined if there is no .type directive.
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

#ifndef ASM_LINE_SEP
# define ASM_LINE_SEP ;
#endif

#ifdef HAVE_ASM_GLOBAL_DOT_NAME
# ifndef C_SYMBOL_DOT_NAME
#  if defined __GNUC__ && defined __GNUC_MINOR__ \
      && (__GNUC__ << 16) + __GNUC_MINOR__ >= (3 << 16) + 1
#   define C_SYMBOL_DOT_NAME(name) .name
#  else
#   define C_SYMBOL_DOT_NAME(name) .##name
#  endif
# endif
#endif

#ifndef __ASSEMBLER__
/* GCC understands weak symbols and aliases; use its interface where
   possible, instead of embedded assembly language.  */

/* Define ALIASNAME as a strong alias for NAME.  */
# define strong_alias(name, aliasname) _strong_alias(name, aliasname)
# define _strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)));

/* This comes between the return type and function name in
   a function definition to make that definition weak.  */
# define weak_function __attribute__ ((weak))
# define weak_const_function __attribute__ ((weak, __const__))

# ifdef HAVE_WEAK_SYMBOLS

/* Define ALIASNAME as a weak alias for NAME.
   If weak aliases are not available, this defines a strong alias.  */
#  define weak_alias(name, aliasname) _weak_alias (name, aliasname)
#  define _weak_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));

/* Declare SYMBOL as weak undefined symbol (resolved to 0 if not defined).  */
#  define weak_extern(symbol) _weak_extern (weak symbol)
#  define _weak_extern(expr) _Pragma (#expr)

# else

#  define weak_alias(name, aliasname) strong_alias(name, aliasname)
#  define weak_extern(symbol) /* Nothing. */

# endif

#else /* __ASSEMBLER__ */

# ifdef HAVE_ASM_SET_DIRECTIVE
#  ifdef HAVE_ASM_GLOBAL_DOT_NAME
#   define strong_alias(original, alias)				\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP		\
  .set C_SYMBOL_NAME (alias),C_SYMBOL_NAME (original) ASM_LINE_SEP	\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_DOT_NAME (alias) ASM_LINE_SEP		\
  .set C_SYMBOL_DOT_NAME (alias),C_SYMBOL_DOT_NAME (original)
#   define strong_data_alias(original, alias)				\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP		\
  .set C_SYMBOL_NAME (alias),C_SYMBOL_NAME (original)
#  else
#   define strong_alias(original, alias)				\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP		\
  .set C_SYMBOL_NAME (alias),C_SYMBOL_NAME (original)
#   define strong_data_alias(original, alias) strong_alias(original, alias)
#  endif
# else
#  ifdef HAVE_ASM_GLOBAL_DOT_NAME
#   define strong_alias(original, alias)				\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP		\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original) ASM_LINE_SEP		\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_DOT_NAME (alias) ASM_LINE_SEP		\
  C_SYMBOL_DOT_NAME (alias) = C_SYMBOL_DOT_NAME (original)
#   define strong_data_alias(original, alias)				\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP		\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)
#  else
#   define strong_alias(original, alias)				\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP		\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)
#   define strong_data_alias(original, alias) strong_alias(original, alias)
#  endif
# endif

# ifdef HAVE_WEAK_SYMBOLS
#  ifdef HAVE_ASM_WEAKEXT_DIRECTIVE
#   ifdef HAVE_ASM_GLOBAL_DOT_NAME
#    define weak_alias(original, alias)					\
  .weakext C_SYMBOL_NAME (alias), C_SYMBOL_NAME (original) ASM_LINE_SEP \
  .weakext C_SYMBOL_DOT_NAME (alias), C_SYMBOL_DOT_NAME (original)
#   else
#    define weak_alias(original, alias)					\
  .weakext C_SYMBOL_NAME (alias), C_SYMBOL_NAME (original)
#   endif
#   define weak_extern(symbol)						\
  .weakext C_SYMBOL_NAME (symbol)

#  else /* ! HAVE_ASM_WEAKEXT_DIRECTIVE */

#   ifdef HAVE_ASM_GLOBAL_DOT_NAME
#    define weak_alias(original, alias)					\
  .weak C_SYMBOL_NAME (alias) ASM_LINE_SEP				\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original) ASM_LINE_SEP		\
  .weak C_SYMBOL_DOT_NAME (alias) ASM_LINE_SEP				\
  C_SYMBOL_DOT_NAME (alias) = C_SYMBOL_DOT_NAME (original)
#   else
#    define weak_alias(original, alias)					\
  .weak C_SYMBOL_NAME (alias) ASM_LINE_SEP				\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)
#   endif

#   define weak_extern(symbol)						\
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

/* Determine the return address.  */
#define RETURN_ADDRESS(nr) \
  __builtin_extract_return_addr (__builtin_return_address (nr))

/* When a reference to SYMBOL is encountered, the linker will emit a
   warning message MSG.  */
#ifdef HAVE_GNU_LD
# ifdef HAVE_ELF

/* We want the .gnu.warning.SYMBOL section to be unallocated.  */
#  ifdef HAVE_ASM_PREVIOUS_DIRECTIVE
#   define __make_section_unallocated(section_string)	\
  asm (".section " section_string "\n\t.previous");
#  elif defined HAVE_ASM_POPSECTION_DIRECTIVE
#   define __make_section_unallocated(section_string)	\
  asm (".pushsection " section_string "\n\t.popsection");
#  else
#   define __make_section_unallocated(section_string)
#  endif

/* Tacking on "\n\t#" to the section name makes gcc put it's bogus
   section attributes on what looks like a comment to the assembler.  */
#  ifdef HAVE_SECTION_QUOTES
#   define __sec_comment "\"\n\t#\""
#  else
#   define __sec_comment "\n\t#"
#  endif
#  define link_warning(symbol, msg) \
  __make_section_unallocated (".gnu.warning." #symbol) \
  static const char __evoke_link_warning_##symbol[]	\
    __attribute__ ((unused, section (".gnu.warning." #symbol __sec_comment))) \
    = msg;
#  define libc_freeres_ptr(decl) \
  __make_section_unallocated ("__libc_freeres_ptrs, \"aw\", @nobits") \
  decl __attribute__ ((section ("__libc_freeres_ptrs" __sec_comment)))
#  define __libc_freeres_fn_section \
  __attribute__ ((section ("__libc_freeres_fn")))
# else /* Not ELF: a.out */
#  ifdef HAVE_XCOFF
/* XCOFF does not support .stabs.
   The native aix linker will remove the .stab and .stabstr sections
   The gnu linker will have a fatal error if there is a relocation for
   symbol in the .stab section.  Silently disable this macro.  */
#   define link_warning(symbol, msg)
#  else
#   define link_warning(symbol, msg)		\
     asm (".stabs \"" msg "\",30,0,0,0\n\t"	\
          ".stabs \"" __SYMBOL_PREFIX #symbol "\",1,0,0,0\n");
#  endif /* XCOFF */
#  define libc_freeres_ptr(decl) decl
#  define __libc_freeres_fn_section
# endif
#else
/* We will never be heard; they will all die horribly.  */
# define link_warning(symbol, msg)
# define libc_freeres_ptr(decl) decl
# define __libc_freeres_fn_section
#endif
#define libc_freeres_fn(name)	\
  static void name (void) __attribute_used__ __libc_freeres_fn_section;	\
  text_set_element (__libc_subfreeres, name);				\
  static void name (void)

/* A canned warning for sysdeps/stub functions.  */
#define	stub_warning(name) \
  link_warning (name, \
		"warning: " #name " is not implemented and will always fail")


/* Declare SYMBOL to be TYPE (`function' or `object') and of SIZE bytes,
   when the assembler supports such declarations (such as in ELF).
   This is only necessary when defining something in assembly, or playing
   funny alias games where the size should be other than what the compiler
   thinks it is.  */
#define declare_symbol(symbol, type, size) \
  declare_symbol_1 (symbol, type, size)
#ifdef ASM_TYPE_DIRECTIVE_PREFIX
# ifdef __ASSEMBLER__
#  define declare_symbol_1(symbol, type, size) \
    .type C_SYMBOL_NAME (symbol), \
	  declare_symbol_1_paste (ASM_TYPE_DIRECTIVE_PREFIX, type), size
#  define declare_symbol_1_paste(a, b)	declare_symbol_1_paste_1 (a,b)
#  define declare_symbol_1_paste_1(a,b)	a##b
# else /* Not __ASSEMBLER__.  */
#  define declare_symbol_1(symbol, type, size) \
    asm (".type " __SYMBOL_PREFIX #symbol ", " \
	 declare_symbol_1_stringify (ASM_TYPE_DIRECTIVE_PREFIX) #type \
	 "\n\t.size " __SYMBOL_PREFIX #symbol ", " #size);
#  define declare_symbol_1_stringify(x) declare_symbol_1_stringify_1 (x)
#  define declare_symbol_1_stringify_1(x) #x
# endif /* __ASSEMBLER__ */
#else
# define declare_symbol_1(symbol, type, size) /* Nothing.  */
#endif


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
  extern void *const __start_##set __attribute__ ((__weak__));		\
  extern void *const __stop_##set __attribute__ ((__weak__));		\
  weak_extern (__start_##set) weak_extern (__stop_##set)

/* Return a pointer (void *const *) to the first element of SET.  */
#  define symbol_set_first_element(set)	(&__start_##set)

/* Return true iff PTR (a void *const *) has been incremented
   past the last element in SET.  */
#  define symbol_set_end_p(set, ptr)	((ptr) >= &__stop_##set)

# else	/* Not ELF: a.out.  */

#  ifdef HAVE_XCOFF
/* XCOFF does not support .stabs.
   The native aix linker will remove the .stab and .stabstr sections
   The gnu linker will have a fatal error if there is a relocation for
   symbol in the .stab section.  Silently disable these macros.  */
#   define text_set_element(set, symbol)
#   define data_set_element(set, symbol)
#   define bss_set_element(set, symbol)
#  else
#   define text_set_element(set, symbol)	\
    asm (".stabs \"" __SYMBOL_PREFIX #set "\",23,0,0," __SYMBOL_PREFIX #symbol)
#   define data_set_element(set, symbol)	\
    asm (".stabs \"" __SYMBOL_PREFIX #set "\",25,0,0," __SYMBOL_PREFIX #symbol)
#   define bss_set_element(set, symbol)	?error Must use initialized data.
#  endif /* XCOFF */
#  define symbol_set_define(set)	void *const (set)[1];
#  define symbol_set_declare(set)	extern void *const (set)[1];

#  define symbol_set_first_element(set)	&(set)[1]
#  define symbol_set_end_p(set, ptr)	(*(ptr) == 0)

# endif	/* ELF.  */
#else
/* We cannot do anything in generial.  */
# define text_set_element(set, symbol) asm ("")
# define data_set_element(set, symbol) asm ("")
# define bss_set_element(set, symbol) asm ("")
# define symbol_set_define(set)		void *const (set)[1];
# define symbol_set_declare(set)	extern void *const (set)[1];

# define symbol_set_first_element(set)	&(set)[1]
# define symbol_set_end_p(set, ptr)	(*(ptr) == 0)
#endif	/* Have GNU ld.  */

#if DO_VERSIONING
# define symbol_version(real, name, version) \
     _symbol_version(real, name, version)
# define default_symbol_version(real, name, version) \
     _default_symbol_version(real, name, version)
# ifdef __ASSEMBLER__
#  ifdef HAVE_ASM_GLOBAL_DOT_NAME
#   define _symbol_version(real, name, version) \
     .symver real, name##@##version ASM_LINE_SEP			\
     .symver .##real, .##name##@##version
#   define _default_symbol_version(real, name, version) \
     .symver real, name##@##@##version ASM_LINE_SEP			\
     .symver .##real, .##name##@##@##version
#  else
#   define _symbol_version(real, name, version) \
     .symver real, name##@##version
#   define _default_symbol_version(real, name, version) \
     .symver real, name##@##@##version
#  endif
# else
#  ifdef HAVE_ASM_GLOBAL_DOT_NAME
#   define _symbol_version(real, name, version) \
     __asm__ (".symver " #real "," #name "@" #version "\n\t"	\
	      ".symver ." #real ",." #name "@" #version)
#   define _default_symbol_version(real, name, version) \
     __asm__ (".symver " #real "," #name "@@" #version "\n\t"	\
	      ".symver ." #real ",." #name "@@" #version)
#  else
#   define _symbol_version(real, name, version) \
     __asm__ (".symver " #real "," #name "@" #version)
#   define _default_symbol_version(real, name, version) \
     __asm__ (".symver " #real "," #name "@@" #version)
#  endif
# endif
#else
# define symbol_version(real, name, version)
# define default_symbol_version(real, name, version) \
  strong_alias(real, name)
#endif

#if defined HAVE_VISIBILITY_ATTRIBUTE && defined SHARED
# define attribute_hidden __attribute__ ((visibility ("hidden")))
#else
# define attribute_hidden
#endif

#if defined HAVE_TLS_MODEL_ATTRIBUTE
# define attribute_tls_model_ie __attribute__ ((tls_model ("initial-exec")))
#else
# define attribute_tls_model_ie
#endif

/* Handling on non-exported internal names.  We have to do this only
   for shared code.  */
#ifdef SHARED
# define INTUSE(name) name##_internal
# define INTDEF(name) strong_alias (name, name##_internal)
# define INTVARDEF(name) \
  _INTVARDEF (name, name##_internal)
# if defined HAVE_VISIBILITY_ATTRIBUTE
#  define _INTVARDEF(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name), \
						   visibility ("hidden")));
# else
#  define _INTVARDEF(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)));
# endif
# define INTDEF2(name, newname) strong_alias (name, newname##_internal)
# define INTVARDEF2(name, newname) _INTVARDEF (name, newname##_internal)
#else
# define INTUSE(name) name
# define INTDEF(name)
# define INTVARDEF(name)
# define INTDEF2(name, newname)
# define INTVARDEF2(name, newname)
#endif

/* The following macros are used for PLT bypassing within libc.so
   (and if needed other libraries similarly).
   First of all, you need to have the function prototyped somewhere,
   say in foo/foo.h:

   int foo (int __bar);

   If calls to foo within libc.so should always go to foo defined in libc.so,
   then in include/foo.h you add:

   libc_hidden_proto (foo)

   line and after the foo function definition:

   int foo (int __bar)
   {
     return __bar;
   }
   libc_hidden_def (foo)

   or

   int foo (int __bar)
   {
     return __bar;
   }
   libc_hidden_weak (foo)

   Simularly for global data. If references to foo within libc.so should
   always go to foo defined in libc.so, then in include/foo.h you add:

   libc_hidden_proto (foo)

   line and after foo's definition:

   int foo = INITIAL_FOO_VALUE;
   libc_hidden_data_def (foo)

   or

   int foo = INITIAL_FOO_VALUE;
   libc_hidden_data_weak (foo)

   If foo is normally just an alias (strong or weak) of some other function,
   you should use the normal strong_alias first, then add libc_hidden_def
   or libc_hidden_weak:

   int baz (int __bar)
   {
     return __bar;
   }
   strong_alias (baz, foo)
   libc_hidden_weak (foo)

   If the function should be internal to multiple objects, say ld.so and
   libc.so, the best way is to use:

   #if !defined NOT_IN_libc || defined IS_IN_rtld
   hidden_proto (foo)
   #endif

   in include/foo.h and the normal macros at all function definitions
   depending on what DSO they belong to.

   If versioned_symbol macro is used to define foo,
   libc_hidden_ver macro should be used, as in:

   int __real_foo (int __bar)
   {
     return __bar;
   }
   versioned_symbol (libc, __real_foo, foo, GLIBC_2_1);
   libc_hidden_ver (__real_foo, foo)  */

#if defined SHARED && defined DO_VERSIONING \
    && !defined HAVE_BROKEN_ALIAS_ATTRIBUTE && !defined NO_HIDDEN
# ifndef __ASSEMBLER__
#  if !defined HAVE_VISIBILITY_ATTRIBUTE \
      || defined HAVE_BROKEN_VISIBILITY_ATTRIBUTE
#   define __hidden_proto_hiddenattr(attrs...)
#  else
#   define __hidden_proto_hiddenattr(attrs...) \
  __attribute__ ((visibility ("hidden"), ##attrs))
#  endif
#  define hidden_proto(name, attrs...) \
  __hidden_proto (name, __GI_##name, ##attrs)
#  define __hidden_proto(name, internal, attrs...) \
  extern __typeof (name) internal; \
  extern __typeof (name) name __asm__ (__hidden_asmname (#internal)) \
  __hidden_proto_hiddenattr (attrs);
#  define __hidden_asmname(name) \
  __hidden_asmname1 (__USER_LABEL_PREFIX__, name)
#  define __hidden_asmname1(prefix, name) __hidden_asmname2(prefix, name)
#  define __hidden_asmname2(prefix, name) #prefix name
#  ifdef HAVE_ASM_SET_DIRECTIVE
#   define __hidden_def1(original, alias)			\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP	\
  .set C_SYMBOL_NAME (alias), C_SYMBOL_NAME (original)
#   ifdef HAVE_ASM_GLOBAL_DOT_NAME
#     define __hidden_dot_def1(original, alias)	 ASM_LINE_SEP	\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_DOT_NAME (alias) ASM_LINE_SEP	\
  .set C_SYMBOL_DOT_NAME (alias), C_SYMBOL_DOT_NAME (original)
#   else
#     define __hidden_dot_def1(original, alias)
#   endif
#  else
#   define __hidden_def1(original, alias)			\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_NAME (alias) ASM_LINE_SEP	\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)
#   ifdef HAVE_ASM_GLOBAL_DOT_NAME
#    define __hidden_dot_def1(original, alias)	ASM_LINE_SEP	\
  ASM_GLOBAL_DIRECTIVE C_SYMBOL_DOT_NAME (alias) ASM_LINE_SEP	\
  C_SYMBOL_DOT_NAME (alias) = C_SYMBOL_DOT_NAME (original)
#   else
#    define __hidden_dot_def1(original, alias)
#   endif
#  endif
#  define __hidden_def2(...) #__VA_ARGS__
#  define __hidden_def3(...) __hidden_def2 (__VA_ARGS__)
#  define hidden_def(name)					\
  __asm__ (__hidden_def3 (__hidden_def1 (__GI_##name, name) \
  __hidden_dot_def1 (__GI_##name, name)));
#  define hidden_data_def(name)					\
  __asm__ (__hidden_def3 (__hidden_def1 (__GI_##name, name)));
#  define hidden_ver(local, name)				\
  __asm__ (__hidden_def3 (__hidden_def1 (local, __GI_##name) \
  __hidden_dot_def1 (local, __GI_##name)));
#  define hidden_data_ver(local, name)				\
  __asm__ (__hidden_def3 (__hidden_def1 (local, __GI_##name)));
#  ifdef HAVE_WEAK_SYMBOLS
#   ifdef HAVE_ASM_WEAKEXT_DIRECTIVE
#    define __hidden_weak1(original, alias)			\
  .weakext C_SYMBOL_NAME (alias), C_SYMBOL_NAME (original)
#    ifdef HAVE_ASM_GLOBAL_DOT_NAME
#     define __hidden_dot_weak1(original, alias)	ASM_LINE_SEP	\
  .weakext C_SYMBOL_DOT_NAME (alias), C_SYMBOL_DOT_NAME (original)
#    else
#     define __hidden_dot_weak1(original, alias)
#    endif
#   else /* ! HAVE_ASM_WEAKEXT_DIRECTIVE */
#    define __hidden_weak1(original, alias)			\
  .weak C_SYMBOL_NAME (alias) ASM_LINE_SEP			\
  C_SYMBOL_NAME (alias) = C_SYMBOL_NAME (original)
#    ifdef HAVE_ASM_GLOBAL_DOT_NAME
#     define __hidden_dot_weak1(original, alias)	ASM_LINE_SEP	\
  .weak C_SYMBOL_DOT_NAME (alias) ASM_LINE_SEP	\
  C_SYMBOL_DOT_NAME (alias) = C_SYMBOL_DOT_NAME (original)
#    else
#     define __hidden_dot_weak1(original, alias)
#    endif
#   endif
#   define hidden_weak(name)					\
  __asm__ (__hidden_def3 (__hidden_weak1 (__GI_##name, name) \
  __hidden_dot_weak1 (__GI_##name, name)));
#   define hidden_data_weak(name)					\
  __asm__ (__hidden_def3 (__hidden_weak1 (__GI_##name, name)));
#  else
#   define hidden_weak(name) hidden_def (name)
#  endif
# else
/* For assembly, we need to do the opposite of what we do in C:
   in assembly gcc __REDIRECT stuff is not in place, so functions
   are defined by its normal name and we need to create the
   __GI_* alias to it, in C __REDIRECT causes the function definition
   to use __GI_* name and we need to add alias to the real name.
   There is no reason to use hidden_weak over hidden_def in assembly,
   but we provide it for consistency with the C usage.
   hidden_proto doesn't make sense for assembly but the equivalent
   is to call via the HIDDEN_JUMPTARGET macro instead of JUMPTARGET.  */
#  define hidden_def(name)	strong_alias (name, __GI_##name)
#  define hidden_weak(name)	hidden_def (name)
#  define hidden_ver(local, name) strong_alias (local, __GI_##name)
#  define hidden_data_def(name)	strong_data_alias (name, __GI_##name)
#  define hidden_data_weak(name)	hidden_data_def (name)
#  define hidden_data_ver(local, name) strong_data_alias (local, __GI_##name)
#  ifdef HAVE_ASM_GLOBAL_DOT_NAME
#   define HIDDEN_JUMPTARGET(name) .__GI_##name
#  else
#   define HIDDEN_JUMPTARGET(name) __GI_##name
#  endif
# endif
#else
# ifndef __ASSEMBLER__
#  define hidden_proto(name, attrs...)
# else
#  define HIDDEN_JUMPTARGET(name) JUMPTARGET(name)
# endif /* Not  __ASSEMBLER__ */
# define hidden_weak(name)
# define hidden_def(name)
# define hidden_ver(local, name)
# define hidden_data_weak(name)
# define hidden_data_def(name)
# define hidden_data_ver(local, name)
#endif

#if !defined NOT_IN_libc
# define libc_hidden_proto(name, attrs...) hidden_proto (name, ##attrs)
# define libc_hidden_def(name) hidden_def (name)
# define libc_hidden_weak(name) hidden_weak (name)
# define libc_hidden_ver(local, name) hidden_ver (local, name)
# define libc_hidden_data_def(name) hidden_data_def (name)
# define libc_hidden_data_weak(name) hidden_data_weak (name)
# define libc_hidden_data_ver(local, name) hidden_data_ver (local, name)
#else
# define libc_hidden_proto(name, attrs...)
# define libc_hidden_def(name)
# define libc_hidden_weak(name)
# define libc_hidden_ver(local, name)
# define libc_hidden_data_def(name)
# define libc_hidden_data_weak(name)
# define libc_hidden_data_ver(local, name)
#endif

#if defined NOT_IN_libc && defined IS_IN_rtld
# define rtld_hidden_proto(name, attrs...) hidden_proto (name, ##attrs)
# define rtld_hidden_def(name) hidden_def (name)
# define rtld_hidden_weak(name) hidden_weak (name)
# define rtld_hidden_ver(local, name) hidden_ver (local, name)
# define rtld_hidden_data_def(name) hidden_data_def (name)
# define rtld_hidden_data_weak(name) hidden_data_weak (name)
# define rtld_hidden_data_ver(local, name) hidden_data_ver (local, name)
#else
# define rtld_hidden_proto(name, attrs...)
# define rtld_hidden_def(name)
# define rtld_hidden_weak(name)
# define rtld_hidden_ver(local, name)
# define rtld_hidden_data_def(name)
# define rtld_hidden_data_weak(name)
# define rtld_hidden_data_ver(local, name)
#endif

#if defined NOT_IN_libc && defined IS_IN_libm
# define libm_hidden_proto(name, attrs...) hidden_proto (name, ##attrs)
# define libm_hidden_def(name) hidden_def (name)
# define libm_hidden_weak(name) hidden_weak (name)
# define libm_hidden_ver(local, name) hidden_ver (local, name)
# define libm_hidden_data_def(name) hidden_data_def (name)
# define libm_hidden_data_weak(name) hidden_data_weak (name)
# define libm_hidden_data_ver(local, name) hidden_data_ver (local, name)
#else
# define libm_hidden_proto(name, attrs...)
# define libm_hidden_def(name)
# define libm_hidden_weak(name)
# define libm_hidden_ver(local, name)
# define libm_hidden_data_def(name)
# define libm_hidden_data_weak(name)
# define libm_hidden_data_ver(local, name)
#endif

#ifdef HAVE_BUILTIN_REDIRECTION
# define libc_hidden_builtin_proto(name, attrs...) libc_hidden_proto (name, ##attrs)
# define libc_hidden_builtin_def(name) libc_hidden_def (name)
# define libc_hidden_builtin_weak(name) libc_hidden_weak (name)
# define libc_hidden_builtin_ver(local, name) libc_hidden_ver (local, name)
#else
# define libc_hidden_builtin_proto(name, attrs...)
# define libc_hidden_builtin_def(name)
# define libc_hidden_builtin_weak(name)
# define libc_hidden_builtin_ver(local, name)
#endif

#endif /* libc-symbols.h */
