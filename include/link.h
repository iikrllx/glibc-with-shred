/* Data structure for communication from the run-time dynamic linker for
   loaded ELF shared objects.
   Copyright (C) 1995-2002, 2003, 2004, 2005 Free Software Foundation, Inc.
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

#ifndef	_LINK_H
#define	_LINK_H	1

#include <elf.h>
#include <dlfcn.h>
#include <stddef.h>
#include <sys/types.h>

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t

#include <bits/elfclass.h>		/* Defines __ELF_NATIVE_CLASS.  */
#include <bits/link.h>
#include <bits/linkmap.h>
#include <dl-lookupcfg.h>
#include <tls.h>		/* Defines USE_TLS.  */

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
     for (dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn)
       if (dyn->d_tag == DT_DEBUG)
	 r_debug = (struct r_debug *) dyn->d_un.d_ptr;
   */
extern ElfW(Dyn) _DYNAMIC[];


/* Some internal data structures of the dynamic linker used in the
   linker map.  We only provide forward declarations.  */
struct libname_list;
struct r_found_version;
struct r_search_path_elem;

/* Forward declaration.  */
struct link_map;

/* Structure to describe a single list of scope elements.  The lookup
   functions get passed an array of pointers to such structures.  */
struct r_scope_elem
{
  /* Array of maps for the scope.  */
  struct link_map **r_list;
  /* Number of entries in the scope.  */
  unsigned int r_nlist;
};


/* Structure to record search path and allocation mechanism.  */
struct r_search_path_struct
  {
    struct r_search_path_elem **dirs;
    int malloced;
  };


/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.

   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.

   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */

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

    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;

    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;

    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
	DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		     + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) *l_phdr;	/* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;		/* Entry point location.  */
    ElfW(Half) l_phnum;		/* Number of program header entries.  */
    ElfW(Half) l_ldnum;	/* Number of dynamic segment entries.  */

    /* Array of DT_NEEDED dependencies and their dependencies, in
       dependency order for symbol lookup (with and without
       duplicates).  There is no entry before the dependencies have
       been loaded.  */
    struct r_scope_elem l_searchlist;

    /* We need a special searchlist to process objects marked with
       DT_SYMBOLIC.  */
    struct r_scope_elem l_symbolic_searchlist;

    /* Dependent object that first caused this object to be loaded.  */
    struct link_map *l_loader;

    /* Symbol hash table.  */
    Elf_Symndx l_nbuckets;
    const Elf_Symndx *l_buckets, *l_chain;

    unsigned int l_opencount;	/* Counter for direct and indirect usage.  */
    unsigned int l_direct_opencount; /* Reference count for dlopen/dlclose.  */
    enum			/* Where this object came from.  */
      {
	lt_executable,		/* The main executable program.  */
	lt_library,		/* Library needed by main executable.  */
	lt_loaded		/* Extra run-time loaded shared object.  */
      } l_type:2;
    unsigned int l_relocated:1;	/* Nonzero if object's relocations done.  */
    unsigned int l_init_called:1; /* Nonzero if DT_INIT function called.  */
    unsigned int l_global:1;	/* Nonzero if object in _dl_global_scope.  */
    unsigned int l_reserved:2;	/* Reserved for internal use.  */
    unsigned int l_phdr_allocated:1; /* Nonzero if the data structure pointed
					to by `l_phdr' is allocated.  */
    unsigned int l_soname_added:1; /* Nonzero if the SONAME is for sure in
				      the l_libname list.  */
    unsigned int l_faked:1;	/* Nonzero if this is a faked descriptor
				   without associated file.  */
    unsigned int l_need_tls_init:1; /* Nonzero if GL(dl_init_static_tls)
				       should be called on this link map
				       when relocation finishes.  */
    unsigned int l_used:1;	/* Nonzero if the DSO is used.  */
    unsigned int l_auditing:1;	/* Nonzero if the DSO is used in auditing.  */
    unsigned int l_audit_any_plt:1; /* Nonzero if at least one audit module
				       is interested in the PLT interception.*/

    /* Array with version names.  */
    unsigned int l_nversions;
    struct r_found_version *l_versions;

    /* Collected information about own RPATH directories.  */
    struct r_search_path_struct l_rpath_dirs;

    /* Collected results of relocation while profiling.  */
    struct reloc_result
    {
      DL_FIXUP_VALUE_TYPE addr;
      struct link_map *bound;
      unsigned int boundndx;
      uint32_t enterexit;
      unsigned int flags;
    } *l_reloc_result;

    /* Pointer to the version information if available.  */
    ElfW(Versym) *l_versyms;

    /* String specifying the path where this object was found.  */
    const char *l_origin;

    /* Start and finish of memory map for this object.  l_map_start
       need not be the same as l_addr.  */
    ElfW(Addr) l_map_start, l_map_end;
    /* End of the executable part of the mapping.  */
    ElfW(Addr) l_text_end;

    /* Default array for 'l_scope'.  */
    struct r_scope_elem *l_scope_mem[4];
    /* Size of array allocated for 'l_scope'.  */
    size_t l_scope_max;
    /* This is an array defining the lookup scope for this link map.
       There are at most three different scope lists.  */
    struct r_scope_elem **l_scope;

    /* A similar array, this time only with the local scope.  This is
       used occasionally.  */
    struct r_scope_elem *l_local_scope[2];

    /* This information is kept to check for sure whether a shared
       object is the same as one already loaded.  */
    dev_t l_dev;
    ino64_t l_ino;

    /* Collected information about own RUNPATH directories.  */
    struct r_search_path_struct l_runpath_dirs;

    /* List of object in order of the init and fini calls.  */
    struct link_map **l_initfini;

    /* List of the dependencies introduced through symbol binding.  */
    unsigned int l_reldepsmax;
    unsigned int l_reldepsact;
    struct link_map **l_reldeps;

    /* Various flag words.  */
    ElfW(Word) l_feature_1;
    ElfW(Word) l_flags_1;
    ElfW(Word) l_flags;

    /* Temporarily used in `dl_close'.  */
    unsigned int l_idx;

    struct link_map_machine l_mach;

    struct
    {
      const ElfW(Sym) *sym;
      int type_class;
      struct link_map *value;
      const ElfW(Sym) *ret;
    } l_lookup_cache;

#ifdef USE_TLS
    /* Thread-local storage related info.  */

    /* Start of the initialization image.  */
    void *l_tls_initimage;
    /* Size of the initialization image.  */
    size_t l_tls_initimage_size;
    /* Size of the TLS block.  */
    size_t l_tls_blocksize;
    /* Alignment requirement of the TLS block.  */
    size_t l_tls_align;
    /* Offset of first byte module alignment.  */
    size_t l_tls_firstbyte_offset;
# ifndef NO_TLS_OFFSET
#  define NO_TLS_OFFSET	0
# endif
    /* For objects present at startup time: offset in the static TLS block.  */
    ptrdiff_t l_tls_offset;
    /* Index of the module in the dtv array.  */
    size_t l_tls_modid;
#endif

    /* Information used to change permission after the relocations are
       done.  */
    ElfW(Addr) l_relro_addr;
    size_t l_relro_size;

    /* Audit information.  This array apparent must be the last in the
       structure.  Never add something after it.  */
    struct auditstate
    {
      uintptr_t cookie;
      unsigned int bindflags;
    } l_audit[0];
  };

/* Version numbers for la_version handshake interface.  */
#define LAV_CURRENT	1

/* Activity types signaled through la_activity.  */
enum
  {
    LA_ACT_CONSISTENT,
    LA_ACT_ADD,
    LA_ACT_DELETE
  };

/* Values representing origin of name for dynamic loading.  */
enum
  {
    LA_SER_ORIG = 0x01,		/* Original name.  */
    LA_SER_LIBPATH = 0x02,	/* Directory from LD_LIBRARY_PATH.  */
    LA_SER_RUNPATH = 0x04,	/* Directory from RPATH/RUNPATH.  */
    LA_SER_CONFIG = 0x08,	/* Found through ldconfig.  */
    LA_SER_DEFAULT = 0x40,	/* Default directory.  */
    LA_SER_SECURE = 0x80	/* Unused.  */
  };

/* Values for la_objopen return value.  */
enum
  {
    LA_FLG_BINDTO = 0x01,	/* Audit symbols bound to this object.  */
    LA_FLG_BINDFROM = 0x02	/* Audit symbols bound from this object.  */
  };

/* Values for la_symbind flags parameter.  */
enum
  {
    LA_SYMB_NOPLTENTER = 0x01,	/* la_pltenter will not be called.  */
    LA_SYMB_NOPLTEXIT = 0x02,	/* la_pltexit will not be called.  */
    LA_SYMB_STRUCTCALL = 0x04,	/* Return value is a structure.  */
    LA_SYMB_DLSYM = 0x08,	/* Binding due to dlsym call.  */
    LA_SYMB_ALTVALUE = 0x10	/* Value has been changed by a previous
				   la_symbind call.  */
  };

#if __ELF_NATIVE_CLASS == 32
# define symbind symbind32
#elif __ELF_NATIVE_CLASS == 64
# define symbind symbind64
#else
# error "__ELF_NATIVE_CLASS must be defined"
#endif

struct dl_phdr_info
  {
    ElfW(Addr) dlpi_addr;
    const char *dlpi_name;
    const ElfW(Phdr) *dlpi_phdr;
    ElfW(Half) dlpi_phnum;

    unsigned long long int dlpi_adds;
    unsigned long long int dlpi_subs;
  };

extern int dl_iterate_phdr (int (*callback) (struct dl_phdr_info *info,
					     size_t size, void *data),
			    void *data);
extern int __dl_iterate_phdr (int (*callback) (struct dl_phdr_info *info,
					       size_t size, void *data),
			      void *data);

#endif /* link.h */
