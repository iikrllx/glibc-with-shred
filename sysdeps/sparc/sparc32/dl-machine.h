/* Machine-dependent ELF dynamic relocation inline functions.  SPARC version.
   Copyright (C) 1996, 1997 Free Software Foundation, Inc.
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

#define ELF_MACHINE_NAME "sparc"

#include <assert.h>
#include <string.h>
#include <link.h>
#include <sys/param.h>


/* Some SPARC opcodes we need to use for self-modifying code.  */
#define OPCODE_NOP	0x01000000 /* nop */
#define OPCODE_CALL	0x40000000 /* call ?; add PC-rel word address */
#define OPCODE_SETHI_G1	0x03000000 /* sethi ?, %g1; add value>>10 */
#define OPCODE_JMP_G1	0x81c06000 /* jmp %g1+?; add lo 10 bits of value */
#define OPCODE_SAVE_SP	0x9de3bfa8 /* save %sp, -(16+6)*4, %sp */


/* Return nonzero iff E_MACHINE is compatible with the running host.  */
static inline int
elf_machine_matches_host (Elf32_Half e_machine)
{
  return e_machine == EM_SPARC;
}


/* Return the link-time address of _DYNAMIC.  Conveniently, this is the
   first element of the GOT.  This must be inlined in a function which
   uses global data.  */
static inline Elf32_Addr
elf_machine_dynamic (void)
{
  register Elf32_Addr *got asm ("%l7");
  return *got;
}

/* Return the run-time load address of the shared object.  */
static inline Elf32_Addr
elf_machine_load_address (void)
{
  register Elf32_Addr pc __asm("%o7"), pic __asm("%l7"), got;

  /* Utilize the fact that a local .got entry will be partially
     initialized at startup awaiting its RELATIVE fixup.  */

  __asm("sethi %%hi(.Load_address),%1\n"
        ".Load_address:\n\t"
        "call 1f\n\t"
        "or %1,%%lo(.Load_address),%1\n"
        "1:\tld [%2+%1],%1"
        : "=r"(pc), "=r"(got) : "r"(pic));

  return pc - got;
}

/* Set up the loaded object described by L so its unrelocated PLT
   entries will jump to the on-demand fixup code in dl-runtime.c.  */

static inline int
elf_machine_runtime_setup (struct link_map *l, int lazy, int profile)
{
  Elf32_Addr *plt;
  extern void _dl_runtime_resolve (Elf32_Word);

  if (l->l_info[DT_JMPREL] && lazy)
    {
      /* The entries for functions in the PLT have not yet been filled in.
	 Their initial contents will arrange when called to set the high 22
	 bits of %g1 with an offset into the .rela.plt section and jump to
	 the beginning of the PLT.  */
      plt = (Elf32_Addr *) (l->l_addr + l->l_info[DT_PLTGOT]->d_un.d_ptr);

      /* The beginning of the PLT does:

	 	save %sp, -64, %sp
	 pltpc:	call _dl_runtime_resolve
		nop
		.word MAP

         This saves the register window containing the arguments, and the
	 PC value (pltpc) implicitly saved in %o7 by the call points near the
	 location where we store the link_map pointer for this object.  */

      plt[0] = OPCODE_SAVE_SP;
      /* Construct PC-relative word address.  */
      plt[1] = OPCODE_CALL | (((Elf32_Addr) &_dl_runtime_resolve -
			       (Elf32_Addr) &plt[1]) >> 2);
      plt[2] = OPCODE_NOP;	/* Fill call delay slot.  */
      plt[3] = (Elf32_Addr) l;
    }

  return lazy;
}

/* This code is used in dl-runtime.c to call the `fixup' function
   and then redirect to the address it returns.  */
#define ELF_MACHINE_RUNTIME_TRAMPOLINE asm ("\
	.globl _dl_runtime_resolve
	.type _dl_runtime_resolve, @function
_dl_runtime_resolve:
	/* Set up the arguments to fixup --
	   %o0 = link_map out of plt0
	   %o1 = offset of reloc entry  */
	ld	[%o7 + 8], %o0
	srl	%g1, 10, %o1
	call	fixup
	 sub	%o1, 4*12, %o1
	jmp	%o0
	 restore
	.size _dl_runtime_resolve, . - _dl_runtime_resolve");

/* The address of the JMP_SLOT reloc is the .plt entry, thus we don't
   dereference the reloc's addr to get the final destination.  Ideally
   there would be a generic way to return the value of the symbol from
   elf_machine_relplt, but as it is, the address of the .plt entry is
   good enough.  */
#define ELF_FIXUP_RETURN_VALUE(map, result)  ((Elf32_Addr) &(result))

/* Nonzero iff TYPE should not be allowed to resolve to one of
   the main executable's symbols, as for a COPY reloc.  */
#define elf_machine_lookup_noexec_p(type) ((type) == R_SPARC_COPY)

/* Nonzero iff TYPE describes relocation of a PLT entry, so
   PLT entries should not be allowed to define the value.  */
#define elf_machine_lookup_noplt_p(type) ((type) == R_SPARC_JMP_SLOT)

/* A reloc type used for ld.so cmdline arg lookups to reject PLT entries.  */
#define ELF_MACHINE_RELOC_NOPLT	R_SPARC_JMP_SLOT

/* The SPARC never uses Elf32_Rel relocations.  */
#define ELF_MACHINE_NO_REL 1

/* The SPARC overlaps DT_RELA and DT_PLTREL.  */
#define ELF_MACHINE_PLTREL_OVERLAP 1

/* The PLT uses Elf32_Rela relocs.  */
#define elf_machine_relplt elf_machine_rela

/* Initial entry point code for the dynamic linker.
   The C function `_dl_start' is the real entry point;
   its return value is the user program's entry point.  */

#define RTLD_START __asm__ ("\
.text
	.globl _start
	.type _start,@function
_start:
  /* Allocate space for functions to drop their arguments.  */
	sub	%sp, 6*4, %sp
  /* Pass pointer to argument block to _dl_start.  */
	call	_dl_start
	 add	%sp, 22*4, %o0
	/* FALTHRU */
	.globl _dl_start_user
	.type _dl_start_user,@function
_dl_start_user:
  /* Load the PIC register.  */
1:	call	2f
	 sethi	%hi(_GLOBAL_OFFSET_TABLE_-(1b-.)), %l7
2:	or	%l7, %lo(_GLOBAL_OFFSET_TABLE_-(1b-.)), %l7
	add	%l7, %o7, %l7
  /* Save the user entry point address in %l0 */
	mov	%o0, %l0
  /* See if we were run as a command with the executable file name as an
     extra leading argument.  If so, adjust the contents of the stack.  */
	sethi	%hi(_dl_skip_args), %g2
	or	%g2, %lo(_dl_skip_args), %g2
	ld	[%l7+%g2], %i0
	ld	[%i0], %i0
	tst	%i0
	beq	3f
	 nop
	/* Find out how far to shift.  */
	ld	[%sp+22*4], %i1		/* load argc */
	sub	%i1, %i0, %i1
	sll	%i0, 2, %i2
	st	%i1, [%sp+22*4]
	add	%sp, 23*4, %i1
	add	%i1, %i2, %i2
	/* Copy down argv */
21:	ld	[%i2], %i3
	add	%i2, 4, %i2
	tst	%i3
	st	%i3, [%i1]
	bne	21b
	 add	%i1, 4, %i1
	/* Copy down env */
22:	ld	[%i2], %i3
	add	%i2, 4, %i2
	tst	%i3
	st	%i3, [%i1]
	bne	22b
	 add	%i1, 4, %i1
	/* Copy down auxiliary table.  */
23:	ld	[%i2], %i3
	ld	[%i2+4], %i4
	add	%i2, 8, %i2
	tst	%i3
	st	%i3, [%i1]
	st	%i4, [%i1+4]
	bne	23b
	 add	%i1, 8, %i1
  /* Load _dl_default_scope[2] to pass to _dl_init_next.  */
3:	sethi	%hi(_dl_default_scope), %g1
	or	%g1, %lo(_dl_default_scope), %g1
	ld	[%l7+%g1], %l1
	ld	[%l1+2*4], %l1
  /* Call _dl_init_next to return the address of an initializer to run.  */
4:	call	_dl_init_next
	 mov	%l1, %o0
	tst	%o0
	beq	5f
	 nop
	jmpl	%o0, %o7
	 nop
	ba,a	4b
  /* Clear the startup flag.  */
5:	sethi	%hi(_dl_starting_up), %g1
	or	%g1, %lo(_dl_starting_up), %g1
	ld	[%l7+%g1], %g1
	st	%g0, [%g1]
  /* Pass our finalizer function to the user in %g1.  */
	sethi	%hi(_dl_fini), %g1
	or	%g1, %lo(_dl_fini), %g1
	ld	[%l7+%g1], %g1
  /* Jump to the user's entry point and deallocate the extra stack we got.  */
	jmp	%l0
	 add	%sp, 6*4, %sp
	.size   _dl_start_user,.-_dl_start_user
.previous");

#ifdef RESOLVE
/* Perform the relocation specified by RELOC and SYM (which is fully resolved).
   MAP is the object containing the reloc.  */

static inline void
elf_machine_rela (struct link_map *map, const Elf32_Rela *reloc,
		  const Elf32_Sym *sym, const struct r_found_version *version,
		  Elf32_Addr *const reloc_addr)
{
  extern unsigned long _dl_hwcap;

  if (ELF32_R_TYPE (reloc->r_info) == R_SPARC_RELATIVE)
    {
#ifndef RTLD_BOOTSTRAP
      if (map != &_dl_rtld_map) /* Already done in rtld itself. */
#endif
	*reloc_addr += map->l_addr + reloc->r_addend;
    }
  else
    {
      const Elf32_Sym *const refsym = sym;
      Elf32_Addr value;
      if (sym->st_shndx != SHN_UNDEF &&
	  ELF32_ST_BIND (sym->st_info) == STB_LOCAL)
	value = map->l_addr;
      else
	{
	  value = RESOLVE (&sym, version, ELF32_R_TYPE (reloc->r_info));
	  if (sym)
	    value += sym->st_value;
	}
      value += reloc->r_addend;	/* Assume copy relocs have zero addend.  */

      switch (ELF32_R_TYPE (reloc->r_info))
	{
	case R_SPARC_COPY:
#ifndef RTLD_BOOTSTRAP
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
#endif
	  break;
	case R_SPARC_GLOB_DAT:
	case R_SPARC_32:
	  *reloc_addr = value;
	  break;
	case R_SPARC_JMP_SLOT:
	  /* For thread safety, write the instructions from the bottom and
	     flush before we overwrite the critical "b,a".  */
	  reloc_addr[2] = OPCODE_JMP_G1 | (value & 0x3ff);
	  if (1 || (_dl_hwcap & 1)) /* HWCAP_SPARC_FLUSH */
	    __asm __volatile ("flush %0+8" : : "r"(reloc_addr));
	  reloc_addr[1] = OPCODE_SETHI_G1 | (value >> 10);
	  if (1 || (_dl_hwcap & 1)) /* HWCAP_SPARC_FLUSH */
	    __asm __volatile ("flush %0+4" : : "r"(reloc_addr));
	  break;
	case R_SPARC_8:
	  *(char *) reloc_addr = value;
	  break;
	case R_SPARC_16:
	  *(short *) reloc_addr = value;
	  break;
	case R_SPARC_DISP8:
	  *(char *) reloc_addr = (value - (Elf32_Addr) reloc_addr);
	  break;
	case R_SPARC_DISP16:
	  *(short *) reloc_addr = (value - (Elf32_Addr) reloc_addr);
	  break;
	case R_SPARC_DISP32:
	  *reloc_addr = (value - (Elf32_Addr) reloc_addr);
	  break;
	case R_SPARC_LO10:
	  *reloc_addr = (*reloc_addr & ~0x3ff) | (value & 0x3ff);
	  break;
	case R_SPARC_WDISP30:
	  *reloc_addr = ((*reloc_addr & 0xc0000000)
			 | ((value - (unsigned int) reloc_addr) >> 2));
	  break;
	case R_SPARC_HI22:
	  *reloc_addr = (*reloc_addr & 0xffc00000) | (value >> 10);
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
elf_machine_lazy_rel (struct link_map *map, const Elf32_Rela *reloc)
{
  switch (ELF32_R_TYPE (reloc->r_info))
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
