/* Generic conversion to and from ANSI_X3.110-1983.
   Copyright (C) 1998-2021 Free Software Foundation, Inc.
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

#include <dlfcn.h>
#include <gconv.h>
#include <stdint.h>
#include <string.h>

/* Data taken from the WG15 tables.  */
static const uint32_t to_ucs4[256] =
{
  /* 0x00 */ 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
  /* 0x08 */ 0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
  /* 0x10 */ 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
  /* 0x18 */ 0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f,
  /* 0x20 */ 0x0020, 0x0021, 0x0022, 0x0000, 0x0000, 0x0025, 0x0026, 0x0027,
  /* 0x28 */ 0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
  /* 0x30 */ 0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
  /* 0x38 */ 0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
  /* 0x40 */ 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
  /* 0x48 */ 0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
  /* 0x50 */ 0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
  /* 0x58 */ 0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
  /* 0x60 */ 0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
  /* 0x68 */ 0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f,
  /* 0x70 */ 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
  /* 0x78 */ 0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x007f,
  /* 0x80 */ 0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
  /* 0x88 */ 0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
  /* 0x90 */ 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
  /* 0x98 */ 0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
  /* 0xa0 */ 0x0000, 0x00a1, 0x00a2, 0x00a3, 0x0024, 0x00a5, 0x0023, 0x00a7,
  /* 0xa8 */ 0x00a4, 0x2018, 0x201c, 0x00ab, 0x2190, 0x2191, 0x2192, 0x2193,
  /* 0xb0 */ 0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00d7, 0x00b5, 0x00b6, 0x00b7,
  /* 0xb8 */ 0x00f7, 0x2019, 0x201d, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,
  /* 0xc0 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  /* 0xc8 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  /* 0xd0 */ 0x2014, 0x00b9, 0x00ae, 0x00a9, 0x2122, 0x266a, 0x2500, 0x2502,
  /* 0xd8 */ 0x2571, 0x2572, 0x25e2, 0x25e3, 0x215b, 0x215c, 0x215d, 0x215e,
  /* 0xe0 */ 0x2126, 0x00c6, 0x00d0, 0x00aa, 0x0126, 0x253c, 0x0132, 0x013f,
  /* 0xe8 */ 0x0141, 0x00d8, 0x0152, 0x00ba, 0x00de, 0x0166, 0x014a, 0x0149,
  /* 0xf0 */ 0x0138, 0x00e6, 0x0111, 0x00f0, 0x0127, 0x0131, 0x0133, 0x0140,
  /* 0xf8 */ 0x0142, 0x00f8, 0x0153, 0x00df, 0x00fe, 0x0167, 0x014b, 0x0000
};

/* The outer array range runs from 0xc1 to 0xcf, the inner range from 0x20
   to 0x7f.  */
static const uint32_t to_ucs4_comb[15][96] =
{
  /* 0xc1 */
  {
    /* 0x20 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x00c0, 0x0000, 0x0000, 0x0000, 0x00c8, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x00cc, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00d2,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00d9, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x00e0, 0x0000, 0x0000, 0x0000, 0x00e8, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x00ec, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00f2,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00f9, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc2 */
  {
    /* 0x20 */ 0x00b4, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x00c1, 0x0000, 0x0106, 0x0000, 0x00c9, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x00cd, 0x0000, 0x0000, 0x0139, 0x0000, 0x0143, 0x00d3,
    /* 0x50 */ 0x0000, 0x0000, 0x0154, 0x015a, 0x0000, 0x00da, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x00dd, 0x0179, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x00e1, 0x0000, 0x0107, 0x0000, 0x00e9, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x00ed, 0x0000, 0x0000, 0x013a, 0x0000, 0x0144, 0x00f3,
    /* 0x70 */ 0x0000, 0x0000, 0x0155, 0x015b, 0x0000, 0x00fa, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x00fd, 0x017a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc3 */
  {
    /* 0x20 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x00c2, 0x0000, 0x0108, 0x0000, 0x00ca, 0x0000, 0x011c,
    /* 0x48 */ 0x0124, 0x00ce, 0x0134, 0x0000, 0x0000, 0x0000, 0x0000, 0x00d4,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x015c, 0x0000, 0x00db, 0x0000, 0x0174,
    /* 0x58 */ 0x0000, 0x0176, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x00e2, 0x0000, 0x0109, 0x0000, 0x00ea, 0x0000, 0x011d,
    /* 0x68 */ 0x0125, 0x00ee, 0x0135, 0x0000, 0x0000, 0x0000, 0x0000, 0x00f4,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x015d, 0x0000, 0x00fb, 0x0000, 0x0175,
    /* 0x78 */ 0x0000, 0x0177, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc4 */
  {
    /* 0x20 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x00c3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x0128, 0x0000, 0x0000, 0x0000, 0x0000, 0x00d1, 0x00d5,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0168, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x00e3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x0129, 0x0000, 0x0000, 0x0000, 0x0000, 0x00f1, 0x00f5,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0169, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc5 */
  {
    /* 0x20 */ 0x00af, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0100, 0x0000, 0x0000, 0x0000, 0x0112, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x012a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x014c,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x016a, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0101, 0x0000, 0x0000, 0x0000, 0x0113, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x012b, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x014d,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x016b, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc6 */
  {
    /* 0x20 */ 0x02d8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0102, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x011e,
    /* 0x48 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x016c, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0103, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x011f,
    /* 0x68 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x016d, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc7 */
  {
    /* 0x20 */ 0x02d9, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0000, 0x0000, 0x010a, 0x0000, 0x0116, 0x0000, 0x0120,
    /* 0x48 */ 0x0000, 0x0130, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x017b, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0000, 0x0000, 0x010b, 0x0000, 0x0117, 0x0000, 0x0121,
    /* 0x68 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x017c, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc8 */
  {
    /* 0x20 */ 0x00a8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x00c4, 0x0000, 0x0000, 0x0000, 0x00cb, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x00cf, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00d6,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00dc, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0178, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x00e4, 0x0000, 0x0000, 0x0000, 0x00eb, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x00ef, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00f6,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00fc, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x00ff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xc9 */
  {
    0x0000,
  },
  /* 0xca */
  {
    /* 0x20 */ 0x02da, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x00c5, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x016e, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x00e5, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x016f, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xcb */
  {
    /* 0x20 */ 0x00b8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0000, 0x0000, 0x00c7, 0x0000, 0x0000, 0x0000, 0x0122,
    /* 0x48 */ 0x0000, 0x0000, 0x0000, 0x0136, 0x013b, 0x0000, 0x0145, 0x0000,
    /* 0x50 */ 0x0000, 0x0000, 0x0156, 0x015e, 0x0162, 0x0000, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0000, 0x0000, 0x00e7, 0x0000, 0x0000, 0x0000, 0x0123,
    /* 0x68 */ 0x0000, 0x0000, 0x0000, 0x0137, 0x013c, 0x0000, 0x0146, 0x0000,
    /* 0x70 */ 0x0000, 0x0000, 0x0157, 0x015f, 0x0163, 0x0000, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xcc */
  {
    0x0000,
  },
  /* 0xcd */
  {
    /* 0x20 */ 0x02dd, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0150,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0170, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0151,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0171, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xce */
  {
    /* 0x20 */ 0x02db, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0104, 0x0000, 0x0000, 0x0000, 0x0118, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x012e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x50 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0172, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0105, 0x0000, 0x0000, 0x0000, 0x0119, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x012f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x70 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0173, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  },
  /* 0xcf */
  {
    /* 0x20 */ 0x02c7, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x28 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x30 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x38 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x40 */ 0x0000, 0x0000, 0x0000, 0x010c, 0x010e, 0x011a, 0x0000, 0x0000,
    /* 0x48 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x013d, 0x0000, 0x0147, 0x0000,
    /* 0x50 */ 0x0000, 0x0000, 0x0158, 0x0160, 0x0164, 0x0000, 0x0000, 0x0000,
    /* 0x58 */ 0x0000, 0x0000, 0x017d, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 0x60 */ 0x0000, 0x0000, 0x0000, 0x010d, 0x010f, 0x011b, 0x0000, 0x0000,
    /* 0x68 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x013e, 0x0000, 0x0148, 0x0000,
    /* 0x70 */ 0x0000, 0x0000, 0x0159, 0x0161, 0x0165, 0x0000, 0x0000, 0x0000,
    /* 0x78 */ 0x0000, 0x0000, 0x017e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
  }
};


static const char from_ucs4[][2] =
{
  /* 0x0000 */ "\x00\x00", "\x01\x00", "\x02\x00", "\x03\x00", "\x04\x00",
  /* 0x0005 */ "\x05\x00", "\x06\x00", "\x07\x00", "\x08\x00", "\x09\x00",
  /* 0x000a */ "\x0a\x00", "\x0b\x00", "\x0c\x00", "\x0d\x00", "\x0e\x00",
  /* 0x000f */ "\x0f\x00", "\x10\x00", "\x11\x00", "\x12\x00", "\x13\x00",
  /* 0x0014 */ "\x14\x00", "\x15\x00", "\x16\x00", "\x17\x00", "\x18\x00",
  /* 0x0019 */ "\x19\x00", "\x1a\x00", "\x1b\x00", "\x1c\x00", "\x1d\x00",
  /* 0x001e */ "\x1e\x00", "\x1f\x00", "\x20\x00", "\x21\x00", "\x22\x00",
  /* 0x0023 */ "\xa6\x00", "\xa4\x00", "\x25\x00", "\x26\x00", "\x27\x00",
  /* 0x0028 */ "\x28\x00", "\x29\x00", "\x2a\x00", "\x2b\x00", "\x2c\x00",
  /* 0x002d */ "\x2d\x00", "\x2e\x00", "\x2f\x00", "\x30\x00", "\x31\x00",
  /* 0x0032 */ "\x32\x00", "\x33\x00", "\x34\x00", "\x35\x00", "\x36\x00",
  /* 0x0037 */ "\x37\x00", "\x38\x00", "\x39\x00", "\x3a\x00", "\x3b\x00",
  /* 0x003c */ "\x3c\x00", "\x3d\x00", "\x3e\x00", "\x3f\x00", "\x40\x00",
  /* 0x0041 */ "\x41\x00", "\x42\x00", "\x43\x00", "\x44\x00", "\x45\x00",
  /* 0x0046 */ "\x46\x00", "\x47\x00", "\x48\x00", "\x49\x00", "\x4a\x00",
  /* 0x004b */ "\x4b\x00", "\x4c\x00", "\x4d\x00", "\x4e\x00", "\x4f\x00",
  /* 0x0050 */ "\x50\x00", "\x51\x00", "\x52\x00", "\x53\x00", "\x54\x00",
  /* 0x0055 */ "\x55\x00", "\x56\x00", "\x57\x00", "\x58\x00", "\x59\x00",
  /* 0x005a */ "\x5a\x00", "\x5b\x00", "\x5c\x00", "\x5d\x00", "\x5e\x00",
  /* 0x005f */ "\x5f\x00", "\x60\x00", "\x61\x00", "\x62\x00", "\x63\x00",
  /* 0x0064 */ "\x64\x00", "\x65\x00", "\x66\x00", "\x67\x00", "\x68\x00",
  /* 0x0069 */ "\x69\x00", "\x6a\x00", "\x6b\x00", "\x6c\x00", "\x6d\x00",
  /* 0x006e */ "\x6e\x00", "\x6f\x00", "\x70\x00", "\x71\x00", "\x72\x00",
  /* 0x0073 */ "\x73\x00", "\x74\x00", "\x75\x00", "\x76\x00", "\x77\x00",
  /* 0x0078 */ "\x78\x00", "\x79\x00", "\x7a\x00", "\x7b\x00", "\x7c\x00",
  /* 0x007d */ "\x7d\x00", "\x7e\x00", "\x7f\x00", "\x80\x00", "\x81\x00",
  /* 0x0082 */ "\x82\x00", "\x83\x00", "\x84\x00", "\x85\x00", "\x86\x00",
  /* 0x0087 */ "\x87\x00", "\x88\x00", "\x89\x00", "\x8a\x00", "\x8b\x00",
  /* 0x008c */ "\x8c\x00", "\x8d\x00", "\x8e\x00", "\x8f\x00", "\x90\x00",
  /* 0x0091 */ "\x91\x00", "\x92\x00", "\x93\x00", "\x94\x00", "\x95\x00",
  /* 0x0096 */ "\x96\x00", "\x97\x00", "\x98\x00", "\x99\x00", "\x9a\x00",
  /* 0x009b */ "\x9b\x00", "\x9c\x00", "\x9d\x00", "\x9e\x00", "\x9f\x00",
  /* 0x00a0 */ "\x00\x00", "\xa1\x00", "\xa2\x00", "\xa3\x00", "\xa8\x00",
  /* 0x00a5 */ "\xa5\x00", "\x00\x00", "\xa7\x00", "\xc8\x20", "\xd3\x00",
  /* 0x00aa */ "\xe3\x00", "\xab\x00", "\x00\x00", "\x00\x00", "\xd2\x00",
  /* 0x00af */ "\xc5\x20", "\xb0\x00", "\xb1\x00", "\xb2\x00", "\xb3\x00",
  /* 0x00b4 */ "\xc2\x20", "\xb5\x00", "\xb6\x00", "\xb7\x00", "\xcb\x20",
  /* 0x00b9 */ "\xd1\x00", "\xeb\x00", "\xbb\x00", "\xbc\x00", "\xbd\x00",
  /* 0x00be */ "\xbe\x00", "\xbf\x00", "\xc1\x41", "\xc2\x41", "\xc3\x41",
  /* 0x00c3 */ "\xc4\x41", "\xc8\x41", "\xca\x41", "\xe1\x00", "\xcb\x43",
  /* 0x00c8 */ "\xc1\x45", "\xc2\x45", "\xc3\x45", "\xc8\x45", "\xc1\x49",
  /* 0x00cd */ "\xc2\x49", "\xc3\x49", "\xc8\x49", "\xe2\x00", "\xc4\x4e",
  /* 0x00d2 */ "\xc1\x4f", "\xc2\x4f", "\xc3\x4f", "\xc4\x4f", "\xc8\x4f",
  /* 0x00d7 */ "\xb4\x00", "\xe9\x00", "\xc1\x55", "\xc2\x55", "\xc3\x55",
  /* 0x00dc */ "\xc8\x55", "\xc2\x59", "\xec\x00", "\xfb\x00", "\xc1\x61",
  /* 0x00e1 */ "\xc2\x61", "\xc3\x61", "\xc4\x61", "\xc8\x61", "\xca\x61",
  /* 0x00e6 */ "\xf1\x00", "\xcb\x63", "\xc1\x65", "\xc2\x65", "\xc3\x65",
  /* 0x00eb */ "\xc8\x65", "\xc1\x69", "\xc2\x69", "\xc3\x69", "\xc8\x69",
  /* 0x00f0 */ "\xf3\x00", "\xc4\x6e", "\xc1\x6f", "\xc2\x6f", "\xc3\x6f",
  /* 0x00f5 */ "\xc4\x6f", "\xc8\x6f", "\xb8\x00", "\xf9\x00", "\xc1\x75",
  /* 0x00fa */ "\xc2\x75", "\xc3\x75", "\xc8\x75", "\xc2\x79", "\xfc\x00",
  /* 0x00ff */ "\xc8\x79", "\xc5\x41", "\xc5\x61", "\xc6\x41", "\xc6\x61",
  /* 0x0104 */ "\xce\x41", "\xce\x61", "\xc2\x43", "\xc2\x63", "\xc3\x43",
  /* 0x0109 */ "\xc3\x63", "\xc7\x43", "\xc7\x63", "\xcf\x43", "\xcf\x63",
  /* 0x010e */ "\xcf\x44", "\xcf\x64", "\x00\x00", "\xf2\x00", "\xc5\x45",
  /* 0x0113 */ "\xc5\x65", "\x00\x00", "\x00\x00", "\xc7\x45", "\xc7\x65",
  /* 0x0118 */ "\xce\x45", "\xce\x65", "\xcf\x45", "\xcf\x65", "\xc3\x47",
  /* 0x011d */ "\xc3\x67", "\xc6\x47", "\xc6\x67", "\xc7\x47", "\xc7\x67",
  /* 0x0122 */ "\xcb\x47", "\xcb\x67", "\xc3\x48", "\xc3\x68", "\xe4\x00",
  /* 0x0127 */ "\xf4\x00", "\xc4\x49", "\xc4\x69", "\xc5\x49", "\xc5\x69",
  /* 0x012c */ "\x00\x00", "\x00\x00", "\xce\x49", "\xce\x69", "\xc7\x49",
  /* 0x0131 */ "\xf5\x00", "\xe6\x00", "\xf6\x00", "\xc3\x4a", "\xc3\x6a",
  /* 0x0136 */ "\xcb\x4b", "\xcb\x6b", "\xf0\x00", "\xc2\x4c", "\xc2\x6c",
  /* 0x013b */ "\xcb\x4c", "\xcb\x6c", "\xcf\x4c", "\xcf\x6c", "\xe7\x00",
  /* 0x0140 */ "\xf7\x00", "\xe8\x00", "\xf8\x00", "\xc2\x4e", "\xc2\x6e",
  /* 0x0145 */ "\xcb\x4e", "\xcb\x6e", "\xcf\x4e", "\xcf\x6e", "\xef\x00",
  /* 0x014a */ "\xee\x00", "\xfe\x00", "\xc5\x4f", "\xc5\x6f", "\x00\x00",
  /* 0x014f */ "\x00\x00", "\xcd\x4f", "\xcd\x6f", "\xea\x00", "\xfa\x00",
  /* 0x0154 */ "\xc2\x52", "\xc2\x72", "\xcb\x52", "\xcb\x72", "\xcf\x52",
  /* 0x0159 */ "\xcf\x72", "\xc2\x53", "\xc2\x73", "\xc3\x53", "\xc3\x73",
  /* 0x015e */ "\xcb\x53", "\xcb\x73", "\xcf\x53", "\xcf\x73", "\xcb\x54",
  /* 0x0163 */ "\xcb\x74", "\xcf\x54", "\xcf\x74", "\xed\x00", "\xfd\x00",
  /* 0x0168 */ "\xc4\x55", "\xc4\x75", "\xc5\x55", "\xc5\x75", "\xc6\x55",
  /* 0x016d */ "\xc6\x75", "\xca\x55", "\xca\x75", "\xcd\x55", "\xcd\x75",
  /* 0x0172 */ "\xce\x55", "\xce\x75", "\xc3\x57", "\xc3\x77", "\xc3\x59",
  /* 0x0177 */ "\xc3\x79", "\xc8\x59", "\xc2\x5a", "\xc2\x7a", "\xc7\x5a",
  /* 0x017c */ "\xc7\x7a", "\xcf\x5a", "\xcf\x7a"
/*
   This table does not cover the following positions:

     0x02c7    "\xcf\x20",
     ...
     0x02d8    "\xc6\x20", "\xc7\x20", "\xca\x20", "\xce\x20", "\x00\x00",
     0x02dd    "\xcd\x20",
     ...
     0x2014    "\xd0\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\xa9\x00",
     0x2019    "\xb9\x00", "\x00\x00", "\x00\x00", "\xaa\x00", "\xba\x00",
     0x201e    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\xd4\x00",
     0x2023    "\x00\x00", "\x00\x00", "\x00\x00", "\xe0\x00",
     ...
     0x215b    "\xdc\x00", "\xdd\x00", "\xde\x00", "\xdf\x00",
     ...
     0x2190    "\xac\x00", "\xad\x00", "\xae\x00", "\xaf\x00",
     ...
     0x2500    "\xd6\x00", "\x00\x00", "\xd7\x00",
     ...
     0x253c    "\xe5\x00",
     ...
     0x2571    "\xd8\x00", "\xd9\x00",
     ...
     0x25e2    "\xda\x00", "\xdb\x00",
     ...
     0x266a    "\xd5\x00",

   These would blow up the table and are therefore handled specially in
   the code.
*/
};


/* Definitions used in the body of the `gconv' function.  */
#define CHARSET_NAME		"ANSI_X3.110//"
#define FROM_LOOP		from_ansi_x3_110
#define TO_LOOP			to_ansi_x3_110
#define DEFINE_INIT		1
#define DEFINE_FINI		1
#define MIN_NEEDED_FROM		1
#define MAX_NEEDED_FROM		2
#define MIN_NEEDED_TO		4
#define ONE_DIRECTION		0

/* First define the conversion function from ANSI_X3.110 to UCS4.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_INPUT	MAX_NEEDED_FROM
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_TO
#define LOOPFCT			FROM_LOOP
#define BODY \
  {									      \
    uint32_t ch = *inptr;						      \
    int incr;								      \
									      \
    if (__builtin_expect (ch >= 0xc1, 0) && ch <= 0xcf)			      \
      {									      \
	/* Composed character.  First test whether the next byte	      \
	   is also available.  */					      \
	uint32_t ch2;							      \
									      \
	if (inptr + 1 >= inend)						      \
	  {								      \
	    /* The second character is not available.  */		      \
	    result = __GCONV_INCOMPLETE_INPUT;				      \
	    break;							      \
	  }								      \
									      \
	ch2 = inptr[1];							      \
									      \
	if (__builtin_expect (ch2 < 0x20, 0)				      \
	    || __builtin_expect (ch2 >= 0x80, 0))			      \
	  {								      \
	    /* This is illegal.  */					      \
	    STANDARD_FROM_LOOP_ERR_HANDLER (1);				      \
	  }								      \
	else								      \
	  {								      \
	    ch = to_ucs4_comb[ch - 0xc1][ch2 - 0x20];			      \
	    incr = 2;							      \
	  }								      \
      }									      \
    else								      \
      {									      \
	ch = to_ucs4[ch];						      \
	incr = 1;							      \
      }									      \
									      \
    if (__builtin_expect (ch == 0, 0) && *inptr != '\0')		      \
      {									      \
	/* This is an illegal character.  */				      \
	STANDARD_FROM_LOOP_ERR_HANDLER (incr);				      \
      }									      \
    else								      \
      {									      \
	put32 (outptr, ch);						      \
	outptr += 4;							      \
      }									      \
									      \
    inptr += incr;							      \
  }
#define LOOP_NEED_FLAGS
#define ONEBYTE_BODY \
  {									      \
    uint32_t ch = to_ucs4[c];						      \
									      \
    if (__builtin_expect (ch == 0, 0) && c != '\0')			      \
      return WEOF;							      \
    else								      \
      return ch;							      \
  }
#include <iconv/loop.c>


/* Next, define the other direction.  */
#define MIN_NEEDED_INPUT	MIN_NEEDED_TO
#define MIN_NEEDED_OUTPUT	MIN_NEEDED_FROM
#define MAX_NEEDED_OUTPUT	MAX_NEEDED_FROM
#define LOOPFCT			TO_LOOP
#define BODY \
  {									      \
    char tmp[2];							      \
    uint32_t ch = get32 (inptr);					      \
    const char *cp;							      \
									      \
    if (__builtin_expect (ch >= sizeof (from_ucs4) / sizeof (from_ucs4[0]),   \
	0))								      \
      {									      \
	if (ch == 0x2c7)						      \
	  cp = "\xcf\x20";						      \
	else if (ch >= 0x2d8 && ch <= 0x2dd && ch != 0x2dc)		      \
	  {								      \
	    static const char map[6] = "\xc6\xc7\xca\xce\x00\xcd";	      \
									      \
	    tmp[0] = map[ch - 0x2d8];					      \
	    tmp[1] = ' ';						      \
	    cp = tmp;							      \
	  }								      \
	else if (ch >= 0x2014 && ch <= 0x201d)				      \
	  {								      \
	    static const char map[10] =					      \
	      "\xd0\x00\x00\x00\xa9\xb9\x00\x00\xaa\xba";		      \
									      \
	    tmp[0] = map[ch - 0x2014];					      \
	    if (tmp[0] == '\0')						      \
	      {								      \
		/* Illegal characters.  */				      \
		STANDARD_TO_LOOP_ERR_HANDLER (4);			      \
	      }								      \
	    tmp[1] = '\0';						      \
	    cp = tmp;							      \
	  }								      \
	else if (ch >= 0x2122 && ch <= 0x2126)				      \
	  {								      \
	    static const char map[5] =					      \
	      "\xd4\x00\x00\x00\xe0";					      \
									      \
	    tmp[0] = map[ch - 0x2122];					      \
	    if (tmp[0] == '\0')						      \
	      {								      \
		/* Illegal characters.  */				      \
		STANDARD_TO_LOOP_ERR_HANDLER (4);			      \
	      }								      \
	    tmp[1] = '\0';						      \
	    cp = tmp;							      \
	  }								      \
	else if (ch >= 0x215b && ch <= 0x215e)				      \
	  {								      \
	    tmp[0] = 0xdc + ch - 0x215b;				      \
	    tmp[1] = '\0';						      \
	    cp = tmp;							      \
	  }								      \
	else if (ch >= 0x2190 && ch <= 0x2193)				      \
	  {								      \
	    tmp[0] = 0xac + ch - 0x2190;				      \
	    tmp[1] = '\0';						      \
	    cp = tmp;							      \
	  }								      \
	else if (ch == 0x2500)						      \
	  cp = "\xd6";							      \
	else if (ch == 0x2502)						      \
	  cp = "\xd7";							      \
	else if (ch == 0x253c)						      \
	  cp = "\xe5";							      \
	else if (ch >= 0x2571 && ch <= 0x2572)				      \
	  {								      \
	    tmp[0] = 0xd8 + ch - 0x2571;				      \
	    tmp[1] = '\0';						      \
	    cp = tmp;							      \
	  }								      \
	else if (ch >= 0x25e2 && ch <= 0x25e3)				      \
	  {								      \
	    tmp[0] = 0xda + ch - 0x25e2;				      \
	    tmp[1] = '\0';						      \
	    cp = tmp;							      \
	  }								      \
	else if (__builtin_expect (ch, 0x266a) == 0x266a)		      \
	  cp = "\xd5";							      \
	else								      \
	  {								      \
	    UNICODE_TAG_HANDLER (ch, 4);				      \
									      \
	    /* Illegal characters.  */					      \
	    STANDARD_TO_LOOP_ERR_HANDLER (4);				      \
	  }								      \
      }									      \
    else								      \
      {									      \
	cp = from_ucs4[ch];						      \
									      \
	if (__builtin_expect (cp[0], '\1') == '\0' && ch != 0)		      \
	  {								      \
	    /* Illegal characters.  */					      \
	    STANDARD_TO_LOOP_ERR_HANDLER (4);				      \
	  }								      \
      }									      \
									      \
    *outptr++ = cp[0];							      \
    /* Now test for a possible second byte and write this if possible.  */    \
    if (cp[1] != '\0')							      \
      {									      \
	if (__glibc_unlikely (outptr >= outend))			      \
	  {								      \
	    /* The result does not fit into the buffer.  */		      \
	    --outptr;							      \
	    result = __GCONV_FULL_OUTPUT;				      \
	    break;							      \
	  }								      \
									      \
	*outptr++ = cp[1];						      \
      }									      \
									      \
    inptr += 4;								      \
  }
#define LOOP_NEED_FLAGS
#include <iconv/loop.c>


/* Now define the toplevel functions.  */
#include <iconv/skeleton.c>
