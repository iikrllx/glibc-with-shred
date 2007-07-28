/* Mapping tables from IBM1008 to IBM420 and vice versa.
   Copyright (C) 2005 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Masahide Washizawa <washi@jp.ibm.com>, 2005.

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

#include <dlfcn.h>
#include <gconv.h>
#include <stdint.h>

static const char __from_ibm1008_to_ibm420[256] =
{
  [0x00] = 0x00, [0x01] = 0x01, [0x02] = 0x02, [0x03] = 0x03, 
  [0x04] = 0x37, [0x05] = 0x2D, [0x06] = 0x2E, [0x07] = 0x2F, 
  [0x08] = 0x16, [0x09] = 0x05, [0x0A] = 0x25, [0x0B] = 0x0B, 
  [0x0C] = 0x0C, [0x0D] = 0x0D, [0x0E] = 0x0E, [0x0F] = 0x0F, 
  [0x10] = 0x10, [0x11] = 0x11, [0x12] = 0x12, [0x13] = 0x13, 
  [0x14] = 0x3C, [0x15] = 0x3D, [0x16] = 0x32, [0x17] = 0x26, 
  [0x18] = 0x18, [0x19] = 0x19, [0x1A] = 0x3F, [0x1B] = 0x27, 
  [0x1C] = 0x1C, [0x1D] = 0x1D, [0x1E] = 0x1E, [0x1F] = 0x1F, 
  [0x20] = 0x40, [0x21] = 0x5A, [0x22] = 0x7F, [0x23] = 0x7B, 
  [0x24] = 0x5B, [0x25] = 0x6C, [0x26] = 0x50, [0x27] = 0x7D, 
  [0x28] = 0x4D, [0x29] = 0x5D, [0x2A] = 0x5C, [0x2B] = 0x4E, 
  [0x2C] = 0x6B, [0x2D] = 0x60, [0x2E] = 0x4B, [0x2F] = 0x61, 
  [0x30] = 0xF0, [0x31] = 0xF1, [0x32] = 0xF2, [0x33] = 0xF3, 
  [0x34] = 0xF4, [0x35] = 0xF5, [0x36] = 0xF6, [0x37] = 0xF7, 
  [0x38] = 0xF8, [0x39] = 0xF9, [0x3A] = 0x7A, [0x3B] = 0x5E, 
  [0x3C] = 0x4C, [0x3D] = 0x7E, [0x3E] = 0x6E, [0x3F] = 0x6F, 
  [0x40] = 0x7C, [0x41] = 0xC1, [0x42] = 0xC2, [0x43] = 0xC3, 
  [0x44] = 0xC4, [0x45] = 0xC5, [0x46] = 0xC6, [0x47] = 0xC7, 
  [0x48] = 0xC8, [0x49] = 0xC9, [0x4A] = 0xD1, [0x4B] = 0xD2, 
  [0x4C] = 0xD3, [0x4D] = 0xD4, [0x4E] = 0xD5, [0x4F] = 0xD6, 
  [0x50] = 0xD7, [0x51] = 0xD8, [0x52] = 0xD9, [0x53] = 0xE2, 
  [0x54] = 0xE3, [0x55] = 0xE4, [0x56] = 0xE5, [0x57] = 0xE6, 
  [0x58] = 0xE7, [0x59] = 0xE8, [0x5A] = 0xE9, [0x5B] = 0x53, 
  [0x5C] = 0x54, [0x5D] = 0xB6, [0x5E] = 0xB7, [0x5F] = 0x6D, 
  [0x60] = 0xCC, [0x61] = 0x81, [0x62] = 0x82, [0x63] = 0x83, 
  [0x64] = 0x84, [0x65] = 0x85, [0x66] = 0x86, [0x67] = 0x87, 
  [0x68] = 0x88, [0x69] = 0x89, [0x6A] = 0x91, [0x6B] = 0x92, 
  [0x6C] = 0x93, [0x6D] = 0x94, [0x6E] = 0x95, [0x6F] = 0x96, 
  [0x70] = 0x97, [0x71] = 0x98, [0x72] = 0x99, [0x73] = 0xA2, 
  [0x74] = 0xA3, [0x75] = 0xA4, [0x76] = 0xA5, [0x77] = 0xA6, 
  [0x78] = 0xA7, [0x79] = 0xA8, [0x7A] = 0xA9, [0x7B] = 0xCE, 
  [0x7C] = 0x4F, [0x7D] = 0xE1, [0x7E] = 0xEC, [0x7F] = 0x07, 
  [0x80] = 0x20, [0x81] = 0x21, [0x82] = 0x22, [0x83] = 0x23, 
  [0x84] = 0x24, [0x85] = 0x15, [0x86] = 0x06, [0x87] = 0x17, 
  [0x88] = 0x28, [0x89] = 0x29, [0x8A] = 0x2A, [0x8B] = 0x2B, 
  [0x8C] = 0x2C, [0x8D] = 0x09, [0x8E] = 0x0A, [0x8F] = 0x1B, 
  [0x90] = 0x30, [0x91] = 0x31, [0x92] = 0x1A, [0x93] = 0x33, 
  [0x94] = 0x34, [0x95] = 0x35, [0x96] = 0x36, [0x97] = 0x08, 
  [0x98] = 0x38, [0x99] = 0x39, [0x9A] = 0x3A, [0x9B] = 0x3B, 
  [0x9C] = 0x04, [0x9D] = 0x14, [0x9E] = 0x3E, [0x9F] = 0xFF, 
  [0xA0] = 0x41, [0xA1] = 0x79, [0xA2] = 0x4A, [0xA3] = 0xC0, 
  [0xA4] = 0xD0, [0xA5] = 0x42, [0xA6] = 0x6A, [0xA7] = 0x43, 
  [0xA8] = 0x44, [0xA9] = 0x45, [0xAA] = 0x46, [0xAB] = 0x47, 
  [0xAC] = 0x5F, [0xAD] = 0xCA, [0xAE] = 0x48, [0xAF] = 0x49, 
  [0xB0] = 0xDF, [0xB1] = 0xEA, [0xB2] = 0xEB, [0xB3] = 0xED, 
  [0xB4] = 0xEE, [0xB5] = 0xEF, [0xB6] = 0xFB, [0xB7] = 0xFC, 
  [0xB8] = 0xFD, [0xB9] = 0xFE, [0xBA] = 0x51, [0xBB] = 0x52, 
  [0xBC] = 0x55, [0xBD] = 0x56, [0xBE] = 0x57, [0xBF] = 0x58, 
  [0xC0] = 0x59, [0xC1] = 0x62, [0xC2] = 0x63, [0xC3] = 0x64, 
  [0xC4] = 0x65, [0xC5] = 0x66, [0xC6] = 0x67, [0xC7] = 0x68, 
  [0xC8] = 0x69, [0xC9] = 0x70, [0xCA] = 0x71, [0xCB] = 0x72, 
  [0xCC] = 0x73, [0xCD] = 0x74, [0xCE] = 0x75, [0xCF] = 0x76, 
  [0xD0] = 0x77, [0xD1] = 0x78, [0xD2] = 0x80, [0xD3] = 0x8A, 
  [0xD4] = 0x8B, [0xD5] = 0x8C, [0xD6] = 0x8D, [0xD7] = 0xE0, 
  [0xD8] = 0x8E, [0xD9] = 0x8F, [0xDA] = 0x90, [0xDB] = 0x9A, 
  [0xDC] = 0x9B, [0xDD] = 0x9C, [0xDE] = 0x9D, [0xDF] = 0x9E, 
  [0xE0] = 0x9F, [0xE1] = 0xA0, [0xE2] = 0xAA, [0xE3] = 0xAB, 
  [0xE4] = 0xAC, [0xE5] = 0xAD, [0xE6] = 0xAE, [0xE7] = 0xAF, 
  [0xE8] = 0xB0, [0xE9] = 0xB1, [0xEA] = 0xB2, [0xEB] = 0xB3, 
  [0xEC] = 0xB4, [0xED] = 0xB5, [0xEE] = 0xB8, [0xEF] = 0xB9, 
  [0xF0] = 0xBA, [0xF1] = 0xBB, [0xF2] = 0xBC, [0xF3] = 0xBD, 
  [0xF4] = 0xBE, [0xF5] = 0xBF, [0xF6] = 0xCB, [0xF7] = 0xA1, 
  [0xF8] = 0xCD, [0xF9] = 0xCF, [0xFA] = 0xDA, [0xFB] = 0xDB, 
  [0xFC] = 0xDC, [0xFD] = 0xDD, [0xFE] = 0xDE, [0xFF] = 0xFA, 
};

static const char __from_ibm420_to_ibm1008[256] =
{
  [0x00] = 0x00, [0x01] = 0x01, [0x02] = 0x02, [0x03] = 0x03, 
  [0x04] = 0x9C, [0x05] = 0x09, [0x06] = 0x86, [0x07] = 0x7F, 
  [0x08] = 0x97, [0x09] = 0x8D, [0x0A] = 0x8E, [0x0B] = 0x0B, 
  [0x0C] = 0x0C, [0x0D] = 0x0D, [0x0E] = 0x0E, [0x0F] = 0x0F, 
  [0x10] = 0x10, [0x11] = 0x11, [0x12] = 0x12, [0x13] = 0x13, 
  [0x14] = 0x9D, [0x15] = 0x85, [0x16] = 0x08, [0x17] = 0x87, 
  [0x18] = 0x18, [0x19] = 0x19, [0x1A] = 0x92, [0x1B] = 0x8F, 
  [0x1C] = 0x1C, [0x1D] = 0x1D, [0x1E] = 0x1E, [0x1F] = 0x1F, 
  [0x20] = 0x80, [0x21] = 0x81, [0x22] = 0x82, [0x23] = 0x83, 
  [0x24] = 0x84, [0x25] = 0x0A, [0x26] = 0x17, [0x27] = 0x1B, 
  [0x28] = 0x88, [0x29] = 0x89, [0x2A] = 0x8A, [0x2B] = 0x8B, 
  [0x2C] = 0x8C, [0x2D] = 0x05, [0x2E] = 0x06, [0x2F] = 0x07, 
  [0x30] = 0x90, [0x31] = 0x91, [0x32] = 0x16, [0x33] = 0x93, 
  [0x34] = 0x94, [0x35] = 0x95, [0x36] = 0x96, [0x37] = 0x04, 
  [0x38] = 0x98, [0x39] = 0x99, [0x3A] = 0x9A, [0x3B] = 0x9B, 
  [0x3C] = 0x14, [0x3D] = 0x15, [0x3E] = 0x9E, [0x3F] = 0x1A, 
  [0x40] = 0x20, [0x41] = 0xA0, [0x42] = 0xA5, [0x43] = 0xA7, 
  [0x44] = 0xA8, [0x45] = 0xA9, [0x46] = 0xAA, [0x47] = 0xAB, 
  [0x48] = 0xAE, [0x49] = 0xAF, [0x4A] = 0xA2, [0x4B] = 0x2E, 
  [0x4C] = 0x3C, [0x4D] = 0x28, [0x4E] = 0x2B, [0x4F] = 0x7C, 
  [0x50] = 0x26, [0x51] = 0xBA, [0x52] = 0xBB, [0x53] = 0x5B, 
  [0x54] = 0x5C, [0x55] = 0xBC, [0x56] = 0xBD, [0x57] = 0xBE, 
  [0x58] = 0xBF, [0x59] = 0xC0, [0x5A] = 0x21, [0x5B] = 0x24, 
  [0x5C] = 0x2A, [0x5D] = 0x29, [0x5E] = 0x3B, [0x5F] = 0xAC, 
  [0x60] = 0x2D, [0x61] = 0x2F, [0x62] = 0xC1, [0x63] = 0xC2, 
  [0x64] = 0xC3, [0x65] = 0xC4, [0x66] = 0xC5, [0x67] = 0xC6, 
  [0x68] = 0xC7, [0x69] = 0xC8, [0x6A] = 0xA6, [0x6B] = 0x2C, 
  [0x6C] = 0x25, [0x6D] = 0x5F, [0x6E] = 0x3E, [0x6F] = 0x3F, 
  [0x70] = 0xC9, [0x71] = 0xCA, [0x72] = 0xCB, [0x73] = 0xCC, 
  [0x74] = 0xCD, [0x75] = 0xCE, [0x76] = 0xCF, [0x77] = 0xD0, 
  [0x78] = 0xD1, [0x79] = 0xA1, [0x7A] = 0x3A, [0x7B] = 0x23, 
  [0x7C] = 0x40, [0x7D] = 0x27, [0x7E] = 0x3D, [0x7F] = 0x22, 
  [0x80] = 0xD2, [0x81] = 0x61, [0x82] = 0x62, [0x83] = 0x63, 
  [0x84] = 0x64, [0x85] = 0x65, [0x86] = 0x66, [0x87] = 0x67, 
  [0x88] = 0x68, [0x89] = 0x69, [0x8A] = 0xD3, [0x8B] = 0xD4, 
  [0x8C] = 0xD5, [0x8D] = 0xD6, [0x8E] = 0xD8, [0x8F] = 0xD9, 
  [0x90] = 0xDA, [0x91] = 0x6A, [0x92] = 0x6B, [0x93] = 0x6C, 
  [0x94] = 0x6D, [0x95] = 0x6E, [0x96] = 0x6F, [0x97] = 0x70, 
  [0x98] = 0x71, [0x99] = 0x72, [0x9A] = 0xDB, [0x9B] = 0xDC, 
  [0x9C] = 0xDD, [0x9D] = 0xDE, [0x9E] = 0xDF, [0x9F] = 0xE0, 
  [0xA0] = 0xE1, [0xA1] = 0xF7, [0xA2] = 0x73, [0xA3] = 0x74, 
  [0xA4] = 0x75, [0xA5] = 0x76, [0xA6] = 0x77, [0xA7] = 0x78, 
  [0xA8] = 0x79, [0xA9] = 0x7A, [0xAA] = 0xE2, [0xAB] = 0xE3, 
  [0xAC] = 0xE4, [0xAD] = 0xE5, [0xAE] = 0xE6, [0xAF] = 0xE7, 
  [0xB0] = 0xE8, [0xB1] = 0xE9, [0xB2] = 0xEA, [0xB3] = 0xEB, 
  [0xB4] = 0xEC, [0xB5] = 0xED, [0xB6] = 0x5D, [0xB7] = 0x5E, 
  [0xB8] = 0xEE, [0xB9] = 0xEF, [0xBA] = 0xF0, [0xBB] = 0xF1, 
  [0xBC] = 0xF2, [0xBD] = 0xF3, [0xBE] = 0xF4, [0xBF] = 0xF5, 
  [0xC0] = 0xA3, [0xC1] = 0x41, [0xC2] = 0x42, [0xC3] = 0x43, 
  [0xC4] = 0x44, [0xC5] = 0x45, [0xC6] = 0x46, [0xC7] = 0x47, 
  [0xC8] = 0x48, [0xC9] = 0x49, [0xCA] = 0xAD, [0xCB] = 0xF6, 
  [0xCC] = 0x60, [0xCD] = 0xF8, [0xCE] = 0x7B, [0xCF] = 0xF9, 
  [0xD0] = 0xA4, [0xD1] = 0x4A, [0xD2] = 0x4B, [0xD3] = 0x4C, 
  [0xD4] = 0x4D, [0xD5] = 0x4E, [0xD6] = 0x4F, [0xD7] = 0x50, 
  [0xD8] = 0x51, [0xD9] = 0x52, [0xDA] = 0xFA, [0xDB] = 0xFB, 
  [0xDC] = 0xFC, [0xDD] = 0xFD, [0xDE] = 0xFE, [0xDF] = 0xB0, 
  [0xE0] = 0xD7, [0xE1] = 0x7D, [0xE2] = 0x53, [0xE3] = 0x54, 
  [0xE4] = 0x55, [0xE5] = 0x56, [0xE6] = 0x57, [0xE7] = 0x58, 
  [0xE8] = 0x59, [0xE9] = 0x5A, [0xEA] = 0xB1, [0xEB] = 0xB2, 
  [0xEC] = 0x7E, [0xED] = 0xB3, [0xEE] = 0xB4, [0xEF] = 0xB5, 
  [0xF0] = 0x30, [0xF1] = 0x31, [0xF2] = 0x32, [0xF3] = 0x33, 
  [0xF4] = 0x34, [0xF5] = 0x35, [0xF6] = 0x36, [0xF7] = 0x37, 
  [0xF8] = 0x38, [0xF9] = 0x39, [0xFA] = 0xFF, [0xFB] = 0xB6, 
  [0xFC] = 0xB7, [0xFD] = 0xB8, [0xFE] = 0xB9, [0xFF] = 0x9F, 
};

#define CHARSET_NAME		"IBM1008//"
#define FROM_LOOP		from_ibm1008_to_ibm420
#define TO_LOOP			from_ibm420_to_ibm1008
#define DEFINE_INIT		1
#define DEFINE_FINI		1
#define MIN_NEEDED_FROM		1
#define MIN_NEEDED_TO		1

/* First define the conversion function from the 8bit charset to UCS4.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_FROM
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_TO
#define LOOPFCT			FROM_LOOP
#define BODY \
  {									      \
    const char ch = __from_ibm1008_to_ibm420[*inptr];			      \
    *outptr++ = ch;							      \
    ++inptr;								      \
  }
#include <iconv/loop.c>


/* Next, define the other direction.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_TO
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_FROM
#define LOOPFCT			TO_LOOP
#define BODY \
  {									      \
    const char ch = __from_ibm420_to_ibm1008[*inptr];			      \
    *outptr++ = ch;							      \
    ++inptr;								      \
  }
#include <iconv/loop.c>

/* Now define the toplevel functions.  */
#include <iconv/skeleton.c>
