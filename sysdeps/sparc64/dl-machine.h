/* Machine-dependent ELF dynamic relocation inline functions.  Sparc64 version.
   Copyright (C) 1997 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#define ELF_MACHINE_NAME "sparc64"

#include <assert.h>
#include <string.h>
#include <link.h>
#include <sys/param.h>
#include <sysdep.h>


/* Return nonzero iff E_MACHINE is compatible with the running host.  */
static inline int
elf_machine_matches_host (Elf64_Half e_machine)
{
  return e_machine == EM_SPARC64;
}


/* Return the link-time address of _DYNAMIC.  Conveniently, this is the
   first element of the GOT.  This must be inlined in a function which
   uses global data.  */
static inline Elf64_Addr
elf_machine_dynamic (void)
{
  register Elf64_Addr *got asm ("%l7");
  return *got;
}


/* Return the run-time load address of the shared object.  */
static inline Elf64_Addr
elf_machine_load_address (void)
{
  Elf64_Addr here;

  __asm("rd %pc,%0\n\t"
	"ba 1f\n\t"
	" add %0,12,%0\n\t"
	".weak __load_address_undefined\n\t"
	"call __load_address_undefined\n"
	"1:"
	: "=r"(here));

  return here + (*(int *)here << 2);
}

#ifdef RESOLVE
/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

static inline void
elf_machine_rela (struct link_map *map, const Elf64_Rela *reloc,
		  const Elf64_Sym *sym, const struct r_found_version *version,
		  Elf64_Addr *const reloc_addr)
{
  Elf64_Addr loadbase;

#ifndef RTLD_BOOTSTRAP
  /* This is defined in rtld.c, but nowhere in the static libc.a; make the
     reference weak so static programs can still link.  This declaration
     cannot be done when compiling rtld.c (i.e.  #ifdef RTLD_BOOTSTRAP)
     because rtld.c contains the common defn for _dl_rtld_map, which is
     incompatible with a weak decl in the same file.  */
  weak_extern (_dl_rtld_map);
#endif

  if (ELF64_R_TYPE (reloc->r_info) == R_SPARC_RELATIVE)
    {
#ifndef RTLD_BOOTSTRAP
      if (map != &_dl_rtld_map) /* Already done in rtld itself. */
#endif
	*reloc_addr += map->l_addr + reloc->r_addend;
    }
  else
    {
      const Elf64_Sym *const refsym = sym;
      Elf64_Addr value;
      if (sym->st_shndx != SHN_UNDEF &&
	  ELF64_ST_BIND (sym->st_info) == STB_LOCAL)
	value = map->l_addr;
      else
	{
	  value = RESOLVE (&sym, version, ELF64_R_TYPE (reloc->r_info));
	  if (sym)
	    value += sym->st_value;
	}
      value += reloc->r_addend;	/* Assume copy relocs have zero addend.  */

      switch (ELF64_R_TYPE (reloc->r_info))
	{
	case R_SPARC_COPY:
	  if (sym->st_size > refsym->st_size
	      || (_dl_verbose && sym->st_size < refsym->st_size))
	    {
	      extern char **_dl_argv;
	      const char *strtab;

	      strtab = ((void *) map->l_addr
			+ map->l_info[DT_STRTAB]->d_un.d_ptr);
	      _dl_sysdep_error (_dl_argv[0] ?: "<program name unknown>",
				": Symbol `", strtab + refsym->st_name,
				"' has different size in shared object, "
				"consider re-linking\n", NULL);
	    }
	  memcpy (reloc_addr, (void *) value, MIN (sym->st_size,
						   refsym->st_size));
	  break;
	case R_SPARC_GLOB_DAT:
	/* case R_SPARC_64: */
	case R_SPARC_JMP_SLOT:
	  *reloc_addr = value;
	  break;
	case R_SPARC_8:
	  *(char *) reloc_addr = value;
	  break;
	case R_SPARC_16:
	  *(short *) reloc_addr = value;
	  break;
	case R_SPARC_DISP8:
	  *(char *) reloc_addr = (value - (Elf64_Addr) reloc_addr);
	  break;
	case R_SPARC_DISP16:
	  *(short *) reloc_addr = (value - (Elf64_Addr) reloc_addr);
	  break;
	case R_SPARC_DISP32:
	  *(unsigned int *)reloc_addr = (value - (Elf64_Addr) reloc_addr);
	  break;
	case R_SPARC_LO10:
	  *(unsigned *)reloc_addr = (*(unsigned *)reloc_addr & ~0x3ff)
				     | (value & 0x3ff);
	  break;
	case R_SPARC_WDISP30:
	  *(unsigned *)reloc_addr = ((*(unsigned *)reloc_addr & 0xc0000000)
			 | ((value - (Elf64_Addr) reloc_addr) >> 2));
	  break;
	case R_SPARC_HI22:
	  *(unsigned *)reloc_addr = (*(unsigned *)reloc_addr & 0xffc00000)
				     | (value >> 10);
	  break;
	case R_SPARC_NONE:		/* Alright, Wilbur.  */
	  break;
	default:
	  assert (! "unexpected dynamic reloc type");
	  break;
	}
    }
}

static inline void
elf_machine_lazy_rel (struct link_map *map, const Elf64_Rela *reloc)
{
  switch (ELF64_R_TYPE (reloc->r_info))
    {
    case R_SPARC_NONE:
      break;
    case R_SPARC_JMP_SLOT:
      break;
    default:
      assert (! "unexpected PLT reloc type");
      break;
    }
}

#endif	/* RESOLVE */

/* Nonzero iff TYPE should not be allowed to resolve to one of
   the main executable's symbols, as for a COPY reloc.  */
#define elf_machine_lookup_noexec_p(type) ((type) == R_SPARC_COPY)

/* Nonzero iff TYPE describes relocation of a PLT entry, so
   PLT entries should not be allowed to define the value.  */
#define elf_machine_lookup_noplt_p(type) ((type) == R_SPARC_JMP_SLOT)

/* A reloc type used for ld.so cmdline arg lookups to reject PLT entries.  */
#define ELF_MACHINE_RELOC_NOPLT	R_SPARC_JMP_SLOT

/* The SPARC never uses Elf64_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1


/* Set up the loaded object described by L so its unrelocated PLT
   entries will jump to the on-demand fixup code in dl-runtime.c.  */

static inline int
elf_machine_runtime_setup (struct link_map *l, int lazy, int profile)
{
  Elf64_Addr *got;
  extern void _dl_runtime_resolve (Elf64_Word);

  if (l->l_info[DT_JMPREL] && lazy)
    {
      got = (Elf64_Addr *) (l->l_addr + l->l_info[DT_PLTGOT]->d_un.d_ptr);
      got[1] = (Elf64_Addr) l;  /* Identify this shared object.  */
      /* This function will get called to fix up the GOT entry indicated by
         the offset on the stack, and then jump to the resolved address.  */
      got[2] = (Elf64_Addr) &_dl_runtime_resolve;
    }

  return lazy;
}

/* This code is used in dl-runtime.c to call the `fixup' function
   and then redirect to the address it returns.  */
#define ELF_MACHINE_RUNTIME_TRAMPOLINE asm ("\
	.globl _dl_runtime_resolve
	.type _dl_runtime_resolve, @function
_dl_runtime_resolve:
	save %sp, -160, %sp
	mov %g1, %o1
	call fixup
	 mov %g2, %o0
	jmp %o0
	 restore
	.size _dl_runtime_resolve, .-_dl_runtime_resolve
");

/* The PLT uses Elf64_Rela relocs.  */
#define elf_machine_relplt elf_machine_rela


/* Mask identifying addresses reserved for the user program,
   where the dynamic linker should not map anything.  */
#define ELF_MACHINE_USER_ADDRESS_MASK	???

/* Initial entry point code for the dynamic linker.
   The C function `_dl_start' is the real entry point;
   its return value is the user program's entry point.  */

#define __S1(x)	#x
#define __S(x)	__S1(x)

#define RTLD_START __asm__ ( "\
	.global _start
	.type _start, @function
_start:
   /* Make room for functions to drop their arguments on the stack.  */
	sub	%sp, 6*8, %sp
   /* Pass pointer to argument block to _dl_start.  */
	call	_dl_start
	 add	 %sp," __S(STACK_BIAS) "+22*8,%o0
	/* FALLTHRU */

	.global _dl_start_user
	.type _dl_start_user, @function
_dl_start_user:
   /* Load the GOT register.  */
1:	rd	%pc,%g1
	sethi	%hi(_GLOBAL_OFFSET_TABLE_-(1b-.)),%l7
	or	%l2,%lo(_GLOBAL_OFFSET_TABLE_-(1b-.)),%l7
	add	%l7,%g1,%l7
   /* Save the user entry point address in %l0.  */
	mov	%o0,%l0
   /* See if we were run as a command with the executable file name as an
      extra leading argument.  If so, adjust the stack pointer.  */
	sethi	%hi(_dl_skip_args), %g2
	or	%g2, %lo(_dl_skip_args), %g2
	ld	[%l7+%g2], %i0
	brz,pt	%i0, 2f
	 ldx	[%sp+" __S(STACK_BIAS) "+22*8], %i1
	sub	%i1, %i0, %i1
	sllx	%i0, 3, %i2
	add	%sp, %i2, %sp
	stx	%i1, [%sp+" __S(STACK_BIAS) "+22*8]
   /* Load _dl_default_scope[2] to pass to _dl_init_next.  */
2:	sethi	%hi(_dl_default_scope), %g2
	or	%g2, %lo(_dl_defalt_scope), %g2
	add	%g2, 2*8, %g2
	ldx	[%l7+%g2], %l1
   /* Call _dl_init_next to return the address of an initializer to run.  */
3:	call	_dl_init_next
	 mov	%l1, %o0
	brz,pn	%o0, 4f
	 nop
	jmpl	%o0, %o7
	 nop
	ba,a	3b
   /* Clear the startup flag.  */
4:	sethi	%hi(_dl_starting_up), %g2
	or	%g2, %lo(_dl_starting_up), %g2
	st	%g0, [%l7+%g2]
   /* Pass our finalizer function to the user in %g1
	sethi	%hi(_dl_fini), %g1
	or	%g1, %lo(_dl_fini), %g1
	ldx	[%l7+%g1], %g1
   /* Jump to the user's entry point & undo the allocation of the xtra regs.  */
	jmp	%l0
	 add	%sp, 6*8, %sp
	.size _dl_start_user, .-_dl_start_user");
