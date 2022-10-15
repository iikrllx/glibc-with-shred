/* This file was generated by: gen-reg-macros.py.

   Copyright (C) 2022 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _REG_MACROS_H
#define _REG_MACROS_H	1

#define rax_8	al
#define rax_16	ax
#define rax_32	eax
#define rax_64	rax
#define rbx_8	bl
#define rbx_16	bx
#define rbx_32	ebx
#define rbx_64	rbx
#define rcx_8	cl
#define rcx_16	cx
#define rcx_32	ecx
#define rcx_64	rcx
#define rdx_8	dl
#define rdx_16	dx
#define rdx_32	edx
#define rdx_64	rdx
#define rbp_8	bpl
#define rbp_16	bp
#define rbp_32	ebp
#define rbp_64	rbp
#define rsp_8	spl
#define rsp_16	sp
#define rsp_32	esp
#define rsp_64	rsp
#define rsi_8	sil
#define rsi_16	si
#define rsi_32	esi
#define rsi_64	rsi
#define rdi_8	dil
#define rdi_16	di
#define rdi_32	edi
#define rdi_64	rdi
#define r8_8	r8b
#define r8_16	r8w
#define r8_32	r8d
#define r8_64	r8
#define r9_8	r9b
#define r9_16	r9w
#define r9_32	r9d
#define r9_64	r9
#define r10_8	r10b
#define r10_16	r10w
#define r10_32	r10d
#define r10_64	r10
#define r11_8	r11b
#define r11_16	r11w
#define r11_32	r11d
#define r11_64	r11
#define r12_8	r12b
#define r12_16	r12w
#define r12_32	r12d
#define r12_64	r12
#define r13_8	r13b
#define r13_16	r13w
#define r13_32	r13d
#define r13_64	r13
#define r14_8	r14b
#define r14_16	r14w
#define r14_32	r14d
#define r14_64	r14
#define r15_8	r15b
#define r15_16	r15w
#define r15_32	r15d
#define r15_64	r15

#define kmov_8	kmovb
#define kmov_16	kmovw
#define kmov_32	kmovd
#define kmov_64	kmovq
#define kortest_8	kortestb
#define kortest_16	kortestw
#define kortest_32	kortestd
#define kortest_64	kortestq
#define kor_8	korb
#define kor_16	korw
#define kor_32	kord
#define kor_64	korq
#define ktest_8	ktestb
#define ktest_16	ktestw
#define ktest_32	ktestd
#define ktest_64	ktestq
#define kand_8	kandb
#define kand_16	kandw
#define kand_32	kandd
#define kand_64	kandq
#define kxor_8	kxorb
#define kxor_16	kxorw
#define kxor_32	kxord
#define kxor_64	kxorq
#define knot_8	knotb
#define knot_16	knotw
#define knot_32	knotd
#define knot_64	knotq
#define kxnor_8	kxnorb
#define kxnor_16	kxnorw
#define kxnor_32	kxnord
#define kxnor_64	kxnorq
#define kunpack_8	kunpackbw
#define kunpack_16	kunpackwd
#define kunpack_32	kunpackdq

/* Common API for accessing proper width GPR is V{upcase_GPR_name}.  */
#define VRAX	VGPR(rax)
#define VRBX	VGPR(rbx)
#define VRCX	VGPR(rcx)
#define VRDX	VGPR(rdx)
#define VRBP	VGPR(rbp)
#define VRSP	VGPR(rsp)
#define VRSI	VGPR(rsi)
#define VRDI	VGPR(rdi)
#define VR8	VGPR(r8)
#define VR9	VGPR(r9)
#define VR10	VGPR(r10)
#define VR11	VGPR(r11)
#define VR12	VGPR(r12)
#define VR13	VGPR(r13)
#define VR14	VGPR(r14)
#define VR15	VGPR(r15)

/* Common API for accessing proper width mask insn is {upcase_mask_insn}.  */
#define KMOV 	VKINSN(kmov)
#define KORTEST 	VKINSN(kortest)
#define KOR 	VKINSN(kor)
#define KTEST 	VKINSN(ktest)
#define KAND 	VKINSN(kand)
#define KXOR 	VKINSN(kxor)
#define KNOT 	VKINSN(knot)
#define KXNOR 	VKINSN(kxnor)
#define KUNPACK 	VKINSN(kunpack)

#ifdef USE_WIDE_CHAR
# define REG_WIDTH 32
#else
# define REG_WIDTH VEC_SIZE
#endif

#define VPASTER(x, y)	x##_##y
#define VEVALUATOR(x, y)	VPASTER(x, y)

#define VGPR_SZ(reg_name, reg_size)	VEVALUATOR(reg_name, reg_size)
#define VKINSN_SZ(insn, reg_size)	VEVALUATOR(insn, reg_size)

#define VGPR(reg_name)	VGPR_SZ(reg_name, REG_WIDTH)
#define VKINSN(mask_insn)	VKINSN_SZ(mask_insn, REG_WIDTH)

#endif
