/* Run-time dynamic linker data structures for loaded ELF shared objects.
   Copyright (C) 1995, 1996, 1997, 1998 Free Software Foundation, Inc.
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

#ifndef	_LINK_H
#define	_LINK_H	1

#include <features.h>

#define __need_size_t
#define __need_NULL
#include <stddef.h>

#include <elf.h>
#include <dlfcn.h>

__BEGIN_DECLS

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define ELFW(type)	_ElfW (ELF, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t

#include <bits/elfclass.h>		/* Defines __ELF_NATIVE_CLASS.  */

/* Rendezvous structure used by the run-time dynamic linker to communicate
   details of shared object loading to the debugger.  If the executable's
   dynamic section has a DT_DEBUG element, the run-time linker sets that
   element's value to the address where this structure can be found.  */

struct r_debug
  {
    int r_version;		/* Version number for this protocol.  */

    struct link_map *r_map;	/* Head of the chain of loaded objects.  */

    /* This is the address of a function internal to the run-time linker,
       that will always be called when the linker begins to map in a
       library or unmap it, and again when the mapping change is complete.
       The debugger can set a breakpoint at this address if it wants to
       notice shared object mapping changes.  */
    ElfW(Addr) r_brk;
    enum
      {
	/* This state value describes the mapping change taking place when
	   the `r_brk' address is called.  */
	RT_CONSISTENT,		/* Mapping change is complete.  */
	RT_ADD,			/* Beginning to add a new object.  */
	RT_DELETE		/* Beginning to remove an object mapping.  */
      } r_state;

    ElfW(Addr) r_ldbase;	/* Base address the linker is loaded at.  */
  };

/* This is the instance of that structure used by the dynamic linker.  */
extern struct r_debug _r_debug;

/* This symbol refers to the "dynamic structure" in the `.dynamic' section
   of whatever module refers to `_DYNAMIC'.  So, to find its own
   `struct r_debug', a program could do:
     for (dyn = _DYNAMIC; dyn->d_tag != DT_NULL)
       if (dyn->d_tag == DT_DEBUG) r_debug = (struct r_debug) dyn->d_un.d_ptr;
   */

extern ElfW(Dyn) _DYNAMIC[];

/* For the version handling we need an array with only names and their
   hash values.  */
struct r_found_version
  {
    const char *name;
    ElfW(Word) hash;

    int hidden;
    const char *filename;
  };

/* We want to cache information about the searches for shared objects.  */

enum r_dir_status { unknown, nonexisting, existing };

struct r_search_path_elem
  {
    const char *dirname;

    size_t dirnamelen;
    enum r_dir_status dirstatus;

    size_t machdirnamelen;
    enum r_dir_status machdirstatus;

    /* Strings saying where the definition came from.  */
    const char *what;
    const char *where;

    /* This link is only used in the `all_dirs' member of `r_search_path'.  */
    struct r_search_path_elem *next;
  };


/* A data structure for a simple single linked list of strings.  */
struct libname_list
  {
    const char *name;		/* Name requested (before search).  */
    struct libname_list *next;	/* Link to next name for this object.  */
  };


/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.

   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.  */

struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Base address shared object is loaded at.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

    /* All following members are internal to the dynamic linker.
       They may change without notice.  */

    struct libname_list  *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_PROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_PROCNUM,DT_NUM+DT_PROCNUM+DT_EXTRANUM) are indexed
       by DT_EXTRATAGIDX(tagvalue) and
       [DT_NUM+DT_PROCNUM+DT_VERSIONTAGNUM,
        DT_NUM+DT_PROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM)
       are indexed by DT_EXTRATAGIDX(tagvalue) (see <elf.h>).  */

    ElfW(Dyn) *l_info[DT_NUM + DT_PROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM];
    const ElfW(Phdr) *l_phdr;	/* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;		/* Entry point location.  */
    ElfW(Half) l_phnum;		/* Number of program header entries.  */

    /* Array of DT_NEEDED dependencies and their dependencies, in
       dependency order for symbol lookup.  This is null before the
       dependencies have been loaded.  */
    struct link_map **l_searchlist;
    unsigned int l_nsearchlist;

    /* We keep another list in which we keep duplicates.  This is
       needed in _dl_lookup_symbol_skip to implemented RTLD_NEXT.  */
    struct link_map **l_dupsearchlist;
    unsigned int l_ndupsearchlist;

    /* Dependent object that first caused this object to be loaded.  */
    struct link_map *l_loader;

    /* Symbol hash table.  */
    ElfW(Symndx) l_nbuckets;
    const ElfW(Symndx) *l_buckets, *l_chain;

    unsigned int l_opencount;	/* Reference count for dlopen/dlclose.  */
    enum			/* Where this object came from.  */
      {
	lt_executable,		/* The main executable program.  */
	lt_library,		/* Library needed by main executable.  */
	lt_loaded		/* Extra run-time loaded shared object.  */
      } l_type:2;
    unsigned int l_relocated:1;	/* Nonzero if object's relocations done.  */
    unsigned int l_init_called:1; /* Nonzero if DT_INIT function called.  */
    unsigned int l_init_running:1; /* Nonzero while DT_INIT function runs.  */
    unsigned int l_global:1;	/* Nonzero if object in _dl_global_scope.  */
    unsigned int l_reserved:2;	/* Reserved for internal use.  */

    /* Array with version names.  */
    unsigned int l_nversions;
    struct r_found_version *l_versions;

    /* Collected information about own RPATH directories.  */
    struct r_search_path_elem **l_rpath_dirs;

    /* Collected results of relocation while profiling.  */
    ElfW(Addr) *l_reloc_result;

    /* Pointer to the version information if available.  */
    ElfW(Half) *l_versyms;
  };


/* Test whether given NAME matches any of the names of the given object.  */
static __inline int
__attribute__ ((unused))
_dl_name_match_p (const char *__name, struct link_map *__map)
{
  int __found = strcmp (__name, __map->l_name) == 0;
  struct libname_list *__runp = __map->l_libname;

  while (! __found && __runp != NULL)
    if (strcmp (__name, __runp->name) == 0)
      __found = 1;
    else
      __runp = __runp->next;

  return __found;
}

/* Function used as argument for `_dl_receive_error' function.  The
   arguments are the error code, error string, and the objname the
   error occurred in.  */
typedef void (*receiver_fct) (int, const char *, const char *);

/* Internal functions of the run-time dynamic linker.
   These can be accessed if you link again the dynamic linker
   as a shared library, as in `-lld' or `/lib/ld.so' explicitly;
   but are not normally of interest to user programs.

   The `-ldl' library functions in <dlfcn.h> provide a simple
   user interface to run-time dynamic linking.  */


/* Parameters passed to the dynamic linker.  */
extern char **_dl_argv;

/* Cached value of `getpagesize ()'.  */
extern size_t _dl_pagesize;

/* File descriptor referring to the zero-fill device.  */
extern int _dl_zerofd;

/* Name of the shared object to be profiled (if any).  */
extern const char *_dl_profile;
/* Map of shared object to be profiled.  */
extern struct link_map *_dl_profile_map;

/* If nonzero the appropriate debug information is printed.  */
extern int _dl_debug_libs;
extern int _dl_debug_impcalls;
extern int _dl_debug_bindings;
extern int _dl_debug_symbols;
extern int _dl_debug_versions;
extern int _dl_debug_reloc;
extern int _dl_debug_files;

/* File deccriptor to write debug messages to.  */
extern int _dl_debug_fd;

/* OS-dependent function to open the zero-fill device.  */
extern int _dl_sysdep_open_zero_fill (void); /* dl-sysdep.c */

/* OS-dependent function to write a message on the specified
   descriptor FD.  All arguments are `const char *'; args until a null
   pointer are concatenated to form the message to print.  */
extern void _dl_sysdep_output (int fd, const char *string, ...);

/* OS-dependent function to write a debug message on the specified
   descriptor for this.  All arguments are `const char *'; args until
   a null pointer are concatenated to form the message to print.  If
   NEW_LINE is nonzero it is assumed that the message starts on a new
   line.*/
extern void _dl_debug_message (int new_line, const char *string, ...);

/* OS-dependent function to write a message on the standard output.
   All arguments are `const char *'; args until a null pointer
   are concatenated to form the message to print.  */
#define _dl_sysdep_message(string, args...) \
  _dl_sysdep_output (STDOUT_FILENO, string, ##args)

/* OS-dependent function to write a message on the standard error.
   All arguments are `const char *'; args until a null pointer
   are concatenated to form the message to print.  */
#define _dl_sysdep_error(string, args...) \
  _dl_sysdep_output (STDERR_FILENO, string, ##args)

/* OS-dependent function to give a fatal error message and exit
   when the dynamic linker fails before the program is fully linked.
   All arguments are `const char *'; args until a null pointer
   are concatenated to form the message to print.  */
#define _dl_sysdep_fatal(string, args...) \
  do									      \
    {									      \
      _dl_sysdep_output (STDERR_FILENO, string, ##args);		      \
      _exit (127);							      \
    }									      \
  while (1)

/* Nonzero if the program should be "secure" (i.e. it's setuid or somesuch).
   This tells the dynamic linker to ignore environment variables.  */
extern int _dl_secure;

/* This function is called by all the internal dynamic linker functions
   when they encounter an error.  ERRCODE is either an `errno' code or
   zero; OBJECT is the name of the problematical shared object, or null if
   it is a general problem; ERRSTRING is a string describing the specific
   problem.  */
extern void _dl_signal_error (int errcode,
			      const char *object,
			      const char *errstring);

/* Call OPERATE, catching errors from `dl_signal_error'.  If there is no
   error, *ERRSTRING is set to null.  If there is an error, *ERRSTRING is
   set to a string constructed from the strings passed to _dl_signal_error,
   and the error code passed is the return value.  ERRSTRING if nonzero
   points to a malloc'ed string which the caller has to free after use.
   ARGS is passed as argument to OPERATE.  */
extern int _dl_catch_error (char **errstring,
			    void (*operate) (void *),
			    void *args);

/* Call OPERATE, receiving errors from `dl_signal_error'.  Unlike
   `_dl_catch_error' the operation is resumed after the OPERATE
   function returns.
   ARGS is passed as argument to OPERATE.  */
extern void _dl_receive_error (receiver_fct fct, void (*operate) (void *),
			       void *args);


/* Helper function for <dlfcn.h> functions.  Runs the OPERATE function via
   _dl_catch_error.  Returns zero for success, nonzero for failure; and
   arranges for `dlerror' to return the error details.
   ARGS is passed as argument to OPERATE.  */
extern int _dlerror_run (void (*operate) (void *), void *args);


/* Open the shared object NAME and map in its segments.
   LOADER's DT_RPATH is used in searching for NAME.
   If the object is already opened, returns its existing map.
   For preloaded shared objects PRELOADED is set to a non-zero
   value to allow additional security checks.  */
extern struct link_map *_dl_map_object (struct link_map *loader,
					const char *name, int preloaded,
					int type, int trace_mode);

/* Call _dl_map_object on the dependencies of MAP, and set up
   MAP->l_searchlist.  PRELOADS points to a vector of NPRELOADS previously
   loaded objects that will be inserted into MAP->l_searchlist after MAP
   but before its dependencies.  */
extern void _dl_map_object_deps (struct link_map *map,
				 struct link_map **preloads,
				 unsigned int npreloads, int trace_mode);

/* Cache the locations of MAP's hash table.  */
extern void _dl_setup_hash (struct link_map *map);


/* Open the shared object NAME, relocate it, and run its initializer if it
   hasn't already been run.  MODE is as for `dlopen' (see <dlfcn.h>).  If
   the object is already opened, returns its existing map.  */
extern struct link_map *_dl_open (const char *name, int mode);

/* Close an object previously opened by _dl_open.  */
extern void _dl_close (struct link_map *map);


/* Search loaded objects' symbol tables for a definition of the symbol
   referred to by UNDEF.  *SYM is the symbol table entry containing the
   reference; it is replaced with the defining symbol, and the base load
   address of the defining object is returned.  SYMBOL_SCOPE is a
   null-terminated list of object scopes to search; each object's
   l_searchlist (i.e. the segment of the dependency tree starting at that
   object) is searched in turn.  REFERENCE_NAME should name the object
   containing the reference; it is used in error messages.
   RELOC_TYPE is a machine-dependent reloc type, which is passed to
   the `elf_machine_lookup_*_p' macros in dl-machine.h to affect which
   symbols can be chosen.  */
extern ElfW(Addr) _dl_lookup_symbol (const char *undef,
				     const ElfW(Sym) **sym,
				     struct link_map *symbol_scope[],
				     const char *reference_name,
				     int reloc_type);

/* Lookup versioned symbol.  */
extern ElfW(Addr) _dl_lookup_versioned_symbol (const char *undef,
					       const ElfW(Sym) **sym,
					       struct link_map *symbol_scope[],
					       const char *reference_name,
					       const struct r_found_version *version,
					       int reloc_type);

/* For handling RTLD_NEXT we must be able to skip shared objects.  */
extern ElfW(Addr) _dl_lookup_symbol_skip (const char *undef,
					  const ElfW(Sym) **sym,
					  struct link_map *symbol_scope[],
					  const char *reference_name,
					  struct link_map *skip_this);

/* For handling RTLD_NEXT with versioned symbols we must be able to
   skip shared objects.  */
extern ElfW(Addr) _dl_lookup_versioned_symbol_skip (const char *undef,
						    const ElfW(Sym) **sym,
						    struct link_map *symbol_scope[],
						    const char *reference_name,
						    const struct r_found_version *version,
						    struct link_map *skip_this);

/* Locate shared object containing the given address.  */
extern int _dl_addr (const void *address, Dl_info *info);

/* Look up symbol NAME in MAP's scope and return its run-time address.  */
extern ElfW(Addr) _dl_symbol_value (struct link_map *map, const char *name);


/* Structure describing the dynamic linker itself.  */
extern struct link_map _dl_rtld_map;

/* The list of objects currently loaded is the third element of the
   `_dl_default_scope' array, and the fourth element is always null.
   This leaves two slots before it that are used when resolving
   DT_SYMBOLIC objects' references one after it for normal references
   (see below).  */
#define _dl_loaded	(_dl_default_scope[2])
extern struct link_map *_dl_default_scope[5];

/* Null-terminated list of objects in the dynamic `global scope'.  The
   list starts at [2]; i.e. &_dl_global_scope[2] is the argument
   passed to _dl_lookup_symbol to search the global scope.  To search
   a specific object and its dependencies in preference to the global
   scope, fill in the [1] slot and pass its address; for two specific
   object scopes, fill [0] and [1].  The list is double-terminated; to
   search the global scope and then a specific object and its
   dependencies, set *_dl_global_scope_end.  This variable initially
   points to _dl_default_scope, and _dl_loaded is always kept in [2]
   of this list.  A new list is malloc'd when new objects are loaded
   with RTLD_GLOBAL.  */
extern struct link_map **_dl_global_scope, **_dl_global_scope_end;
extern size_t _dl_global_scope_alloc; /* Number of slots malloc'd.  */

/* Hack _dl_global_scope[0] and [1] as necessary, and return a pointer into
   _dl_global_scope that should be passed to _dl_lookup_symbol for symbol
   references made in the object MAP's relocations.  */
extern struct link_map **_dl_object_relocation_scope (struct link_map *map);


/* Allocate a `struct link_map' for a new object being loaded,
   and enter it into the _dl_loaded list.  */
extern struct link_map *_dl_new_object (char *realname, const char *libname,
					int type);

/* Relocate the given object (if it hasn't already been).
   SCOPE is passed to _dl_lookup_symbol in symbol lookups.
   If LAZY is nonzero, don't relocate its PLT.  */
extern void _dl_relocate_object (struct link_map *map,
				 struct link_map *scope[],
				 int lazy);

/* Check the version dependencies of all objects available through
   MAP.  If VERBOSE print some more diagnostics.  */
extern int _dl_check_all_versions (struct link_map *map, int verbose);

/* Check the version dependencies for MAP.  If VERBOSE print some more
   diagnostics.  */
extern int _dl_check_map_versions (struct link_map *map, int verbose);

/* Return the address of the next initializer function for MAP or one of
   its dependencies that has not yet been run.  When there are no more
   initializers to be run, this returns zero.  The functions are returned
   in the order they should be called.  */
extern ElfW(Addr) _dl_init_next (struct link_map *map);

/* Call the finalizer functions of all shared objects whose
   initializer functions have completed.  */
extern void _dl_fini (void);

/* The dynamic linker calls this function before and having changing
   any shared object mappings.  The `r_state' member of `struct r_debug'
   says what change is taking place.  This function's address is
   the value of the `r_brk' member.  */
extern void _dl_debug_state (void);

/* Initialize `struct r_debug' if it has not already been done.  The
   argument is the run-time load address of the dynamic linker, to be put
   in the `r_ldbase' member.  Returns the address of the structure.  */
extern struct r_debug *_dl_debug_initialize (ElfW(Addr) ldbase);

/* Initialize the basic data structure for the search paths.  */
extern void _dl_init_paths (const char *library_path);

/* Gather the information needed to install the profiling tables and start
   the timers.  */
extern void _dl_start_profile (struct link_map *map, const char *output_dir);

/* The actual functions used to keep book on the calls.  */
extern void _dl_mcount (ElfW(Addr) frompc, ElfW(Addr) selfpc);


/* Show the members of the auxiliary array passed up from the kernel.  */
extern void _dl_show_auxv (void);

/* Return all environment variables starting with `LD_', one after the
   other.  */
extern char *_dl_next_ld_env_entry (char ***position);

__END_DECLS

#endif /* link.h */
