/* Generic asm macros used on many machines.
   Copyright (C) 1991,92,93,96,98,2002,2003 Free Software Foundation, Inc.
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

#ifndef C_LABEL

/* Define a macro we can use to construct the asm name for a C symbol.  */
#ifdef	NO_UNDERSCORES
#ifdef	__STDC__
#define C_LABEL(name)		name##:
#else
#define C_LABEL(name)		name/**/:
#endif
#else
#ifdef	__STDC__
#define C_LABEL(name)		_##name##:
#else
#define C_LABEL(name)		_/**/name/**/:
#endif
#endif

#endif

#ifdef __ASSEMBLER__
/* Mark the end of function named SYM.  This is used on some platforms
   to generate correct debugging information.  */
#ifndef END
#define END(sym)
#endif

#ifndef JUMPTARGET
#define JUMPTARGET(sym)		sym
#endif

/* Makros to generate eh_frame unwind information.  */
# ifdef HAVE_ASM_CFI_DIRECTIVES
#  define cfi_startproc			.cfi_startproc
#  define cfi_endproc			.cfi_endproc
#  define cfi_def_cfa(reg, off)		.cfi_def_cfa reg, off
#  define cfi_def_cfa_register(reg)	.cfi_def_cfa_register reg
#  define cfi_def_cfa_offset(off)	.cfi_def_cfa_offset off
#  define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
#  define cfi_offset(reg, off)		.cfi_offset reg, off
#  define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
#  define cfi_register(r1, r2)		.cfi_register r1, r2
#  define cfi_return_column(reg)	.cfi_return_column reg
#  define cfi_restore(reg)		.cfi_restore reg
#  define cfi_undefined(reg)		.cfi_undefined reg
#  define cfi_remember_state		.cfi_remember_state
#  define cfi_restore_state		.cfi_restore_state
#  define cfi_window_save		.cfi_window_save
# else
#  define cfi_startproc
#  define cfi_endproc
#  define cfi_def_cfa(reg, off)
#  define cfi_def_cfa_register(reg)
#  define cfi_def_cfa_offset(off)
#  define cfi_adjust_cfa_offset(off)
#  define cfi_offset(reg, off)
#  define cfi_rel_offset(reg, off)
#  define cfi_register(r1, r2)
#  define cfi_return_column(reg)
#  define cfi_restore(reg)
#  define cfi_undefined(reg)
#  define cfi_remember_state
#  define cfi_restore_state
#  define cfi_window_save
# endif

#else /* ! ASSEMBLER */
# ifdef HAVE_ASM_CFI_DIRECTIVES
#  define CFI_STRINGIFY(Name) CFI_STRINGIFY2 (Name)
#  define CFI_STRINGIFY2(Name) #Name
#  define CFI_STARTPROC	".cfi_startproc"
#  define CFI_ENDPROC	".cfi_endproc"
#  define CFI_DEF_CFA(reg, off)	\
   ".cfi_def_cfa " CFI_STRINGIFY(reg) "," CFI_STRINGIFY(off)
#  define CFI_DEF_CFA_REGISTER(reg) \
   ".cfi_def_cfa_register " CFI_STRINGIFY(reg)
#  define CFI_DEF_CFA_OFFSET(off) \
   ".cfi_def_cfa_offset " CFI_STRINGIFY(off)
#  define CFI_ADJUST_CFA_OFFSET(off) \
   ".cfi_adjust_cfa_offset " CFI_STRINGIFY(off)
#  define CFI_OFFSET(reg, off) \
   ".cfi_offset " CFI_STRINGIFY(reg) "," CFI_STRINGIFY(off)
#  define CFI_REL_OFFSET(reg, off) \
   ".cfi_rel_offset " CFI_STRINGIFY(reg) "," CFI_STRINGIFY(off)
#  define CFI_REGISTER(r1, r2) \
   ".cfi_register " CFI_STRINGIFY(r1) "," CFI_STRINGIFY(r2)
#  define CFI_RETURN_COLUMN(reg) \
   ".cfi_return_column " CFI_STRINGIFY(reg)
#  define CFI_RESTORE(reg) \
   ".cfi_restore " CFI_STRINGIFY(reg)
#  define CFI_UNDEFINED(reg) \
   ".cfi_undefined " CFI_STRINGIFY(reg)
#  define CFI_REMEMBER_STATE \
   ".cfi_remember_state"
#  define CFI_RESTORE_STATE \
   ".cfi_restore_state"
#  define CFI_WINDOW_SAVE \
   ".cfi_window_save"
# else
#  define CFI_STARTPROC
#  define CFI_ENDPROC
#  define CFI_DEF_CFA(reg, off)
#  define CFI_DEF_CFA_REGISTER(reg)
#  define CFI_DEF_CFA_OFFSET(off)
#  define CFI_ADJUST_CFA_OFFSET(off)
#  define CFI_OFFSET(reg, off)
#  define CFI_REL_OFFSET(reg, off)
#  define CFI_REGISTER(r1, r2)
#  define CFI_RETURN_COLUMN(reg)
#  define CFI_RESTORE(reg)
#  define CFI_UNDEFINED(reg)
#  define CFI_REMEMBER_STATE
#  define CFI_RESTORE_STATE
#  define CFI_WINDOW_SAVE
# endif

#endif /* __ASSEMBLER__ */
