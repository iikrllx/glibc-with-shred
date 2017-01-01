/* Mapping table for CP775.
   Copyright (C) 1998-2017 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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
   <http://www.gnu.org/licenses/>.  */

#include <stdint.h>

/* Table to map to UCS4.  It can be generated using
   (I know, this is a useless use of cat, but the linebreak requires it):

   cat .../unix/mappings/vendors/micsft/pc/cp775.txt |
   sed -e 's/\(0x..\)[[:space:]]*\(0x....\).*$/  [\1] = \2,/p' -e d

 */
static const uint32_t to_ucs4[256] =
{
  [0x00] = 0x0000,
  [0x01] = 0x0001,
  [0x02] = 0x0002,
  [0x03] = 0x0003,
  [0x04] = 0x0004,
  [0x05] = 0x0005,
  [0x06] = 0x0006,
  [0x07] = 0x0007,
  [0x08] = 0x0008,
  [0x09] = 0x0009,
  [0x0a] = 0x000a,
  [0x0b] = 0x000b,
  [0x0c] = 0x000c,
  [0x0d] = 0x000d,
  [0x0e] = 0x000e,
  [0x0f] = 0x000f,
  [0x10] = 0x0010,
  [0x11] = 0x0011,
  [0x12] = 0x0012,
  [0x13] = 0x0013,
  [0x14] = 0x0014,
  [0x15] = 0x0015,
  [0x16] = 0x0016,
  [0x17] = 0x0017,
  [0x18] = 0x0018,
  [0x19] = 0x0019,
  [0x1a] = 0x001a,
  [0x1b] = 0x001b,
  [0x1c] = 0x001c,
  [0x1d] = 0x001d,
  [0x1e] = 0x001e,
  [0x1f] = 0x001f,
  [0x20] = 0x0020,
  [0x21] = 0x0021,
  [0x22] = 0x0022,
  [0x23] = 0x0023,
  [0x24] = 0x0024,
  [0x25] = 0x0025,
  [0x26] = 0x0026,
  [0x27] = 0x0027,
  [0x28] = 0x0028,
  [0x29] = 0x0029,
  [0x2a] = 0x002a,
  [0x2b] = 0x002b,
  [0x2c] = 0x002c,
  [0x2d] = 0x002d,
  [0x2e] = 0x002e,
  [0x2f] = 0x002f,
  [0x30] = 0x0030,
  [0x31] = 0x0031,
  [0x32] = 0x0032,
  [0x33] = 0x0033,
  [0x34] = 0x0034,
  [0x35] = 0x0035,
  [0x36] = 0x0036,
  [0x37] = 0x0037,
  [0x38] = 0x0038,
  [0x39] = 0x0039,
  [0x3a] = 0x003a,
  [0x3b] = 0x003b,
  [0x3c] = 0x003c,
  [0x3d] = 0x003d,
  [0x3e] = 0x003e,
  [0x3f] = 0x003f,
  [0x40] = 0x0040,
  [0x41] = 0x0041,
  [0x42] = 0x0042,
  [0x43] = 0x0043,
  [0x44] = 0x0044,
  [0x45] = 0x0045,
  [0x46] = 0x0046,
  [0x47] = 0x0047,
  [0x48] = 0x0048,
  [0x49] = 0x0049,
  [0x4a] = 0x004a,
  [0x4b] = 0x004b,
  [0x4c] = 0x004c,
  [0x4d] = 0x004d,
  [0x4e] = 0x004e,
  [0x4f] = 0x004f,
  [0x50] = 0x0050,
  [0x51] = 0x0051,
  [0x52] = 0x0052,
  [0x53] = 0x0053,
  [0x54] = 0x0054,
  [0x55] = 0x0055,
  [0x56] = 0x0056,
  [0x57] = 0x0057,
  [0x58] = 0x0058,
  [0x59] = 0x0059,
  [0x5a] = 0x005a,
  [0x5b] = 0x005b,
  [0x5c] = 0x005c,
  [0x5d] = 0x005d,
  [0x5e] = 0x005e,
  [0x5f] = 0x005f,
  [0x60] = 0x0060,
  [0x61] = 0x0061,
  [0x62] = 0x0062,
  [0x63] = 0x0063,
  [0x64] = 0x0064,
  [0x65] = 0x0065,
  [0x66] = 0x0066,
  [0x67] = 0x0067,
  [0x68] = 0x0068,
  [0x69] = 0x0069,
  [0x6a] = 0x006a,
  [0x6b] = 0x006b,
  [0x6c] = 0x006c,
  [0x6d] = 0x006d,
  [0x6e] = 0x006e,
  [0x6f] = 0x006f,
  [0x70] = 0x0070,
  [0x71] = 0x0071,
  [0x72] = 0x0072,
  [0x73] = 0x0073,
  [0x74] = 0x0074,
  [0x75] = 0x0075,
  [0x76] = 0x0076,
  [0x77] = 0x0077,
  [0x78] = 0x0078,
  [0x79] = 0x0079,
  [0x7a] = 0x007a,
  [0x7b] = 0x007b,
  [0x7c] = 0x007c,
  [0x7d] = 0x007d,
  [0x7e] = 0x007e,
  [0x7f] = 0x007f,
  [0x80] = 0x0106,
  [0x81] = 0x00fc,
  [0x82] = 0x00e9,
  [0x83] = 0x0101,
  [0x84] = 0x00e4,
  [0x85] = 0x0123,
  [0x86] = 0x00e5,
  [0x87] = 0x0107,
  [0x88] = 0x0142,
  [0x89] = 0x0113,
  [0x8a] = 0x0156,
  [0x8b] = 0x0157,
  [0x8c] = 0x012b,
  [0x8d] = 0x0179,
  [0x8e] = 0x00c4,
  [0x8f] = 0x00c5,
  [0x90] = 0x00c9,
  [0x91] = 0x00e6,
  [0x92] = 0x00c6,
  [0x93] = 0x014d,
  [0x94] = 0x00f6,
  [0x95] = 0x0122,
  [0x96] = 0x00a2,
  [0x97] = 0x015a,
  [0x98] = 0x015b,
  [0x99] = 0x00d6,
  [0x9a] = 0x00dc,
  [0x9b] = 0x00f8,
  [0x9c] = 0x00a3,
  [0x9d] = 0x00d8,
  [0x9e] = 0x00d7,
  [0x9f] = 0x00a4,
  [0xa0] = 0x0100,
  [0xa1] = 0x012a,
  [0xa2] = 0x00f3,
  [0xa3] = 0x017b,
  [0xa4] = 0x017c,
  [0xa5] = 0x017a,
  [0xa6] = 0x201d,
  [0xa7] = 0x00a6,
  [0xa8] = 0x00a9,
  [0xa9] = 0x00ae,
  [0xaa] = 0x00ac,
  [0xab] = 0x00bd,
  [0xac] = 0x00bc,
  [0xad] = 0x0141,
  [0xae] = 0x00ab,
  [0xaf] = 0x00bb,
  [0xb0] = 0x2591,
  [0xb1] = 0x2592,
  [0xb2] = 0x2593,
  [0xb3] = 0x2502,
  [0xb4] = 0x2524,
  [0xb5] = 0x0104,
  [0xb6] = 0x010c,
  [0xb7] = 0x0118,
  [0xb8] = 0x0116,
  [0xb9] = 0x2563,
  [0xba] = 0x2551,
  [0xbb] = 0x2557,
  [0xbc] = 0x255d,
  [0xbd] = 0x012e,
  [0xbe] = 0x0160,
  [0xbf] = 0x2510,
  [0xc0] = 0x2514,
  [0xc1] = 0x2534,
  [0xc2] = 0x252c,
  [0xc3] = 0x251c,
  [0xc4] = 0x2500,
  [0xc5] = 0x253c,
  [0xc6] = 0x0172,
  [0xc7] = 0x016a,
  [0xc8] = 0x255a,
  [0xc9] = 0x2554,
  [0xca] = 0x2569,
  [0xcb] = 0x2566,
  [0xcc] = 0x2560,
  [0xcd] = 0x2550,
  [0xce] = 0x256c,
  [0xcf] = 0x017d,
  [0xd0] = 0x0105,
  [0xd1] = 0x010d,
  [0xd2] = 0x0119,
  [0xd3] = 0x0117,
  [0xd4] = 0x012f,
  [0xd5] = 0x0161,
  [0xd6] = 0x0173,
  [0xd7] = 0x016b,
  [0xd8] = 0x017e,
  [0xd9] = 0x2518,
  [0xda] = 0x250c,
  [0xdb] = 0x2588,
  [0xdc] = 0x2584,
  [0xdd] = 0x258c,
  [0xde] = 0x2590,
  [0xdf] = 0x2580,
  [0xe0] = 0x00d3,
  [0xe1] = 0x00df,
  [0xe2] = 0x014c,
  [0xe3] = 0x0143,
  [0xe4] = 0x00f5,
  [0xe5] = 0x00d5,
  [0xe6] = 0x00b5,
  [0xe7] = 0x0144,
  [0xe8] = 0x0136,
  [0xe9] = 0x0137,
  [0xea] = 0x013b,
  [0xeb] = 0x013c,
  [0xec] = 0x0146,
  [0xed] = 0x0112,
  [0xee] = 0x0145,
  [0xef] = 0x2019,
  [0xf0] = 0x00ad,
  [0xf1] = 0x00b1,
  [0xf2] = 0x201c,
  [0xf3] = 0x00be,
  [0xf4] = 0x00b6,
  [0xf5] = 0x00a7,
  [0xf6] = 0x00f7,
  [0xf7] = 0x201e,
  [0xf8] = 0x00b0,
  [0xf9] = 0x2219,
  [0xfa] = 0x00b7,
  [0xfb] = 0x00b9,
  [0xfc] = 0x00b3,
  [0xfd] = 0x00b2,
  [0xfe] = 0x25a0,
  [0xff] = 0x00a0,
};


/* Index table for mapping from UCS4.  The table can be generated with

   cat .../unix/mappings/vendors/micsft/pc/cp775.txt |
   awk '/^0x/ { if (NF > 2) print $2; }' | perl gap.pl

   where gap.pl is the file in this directory.
 */
static const struct gap from_idx[] =
{
  { .start = 0x0000, .end = 0x007f, .idx =     0 },
  { .start = 0x00a0, .end = 0x00c9, .idx =   -32 },
  { .start = 0x00d3, .end = 0x00e9, .idx =   -41 },
  { .start = 0x00f3, .end = 0x0119, .idx =   -50 },
  { .start = 0x0122, .end = 0x0123, .idx =   -58 },
  { .start = 0x012a, .end = 0x012f, .idx =   -64 },
  { .start = 0x0136, .end = 0x014d, .idx =   -70 },
  { .start = 0x0156, .end = 0x0161, .idx =   -78 },
  { .start = 0x016a, .end = 0x016b, .idx =   -86 },
  { .start = 0x0172, .end = 0x017e, .idx =   -92 },
  { .start = 0x2019, .end = 0x201e, .idx = -7926 },
  { .start = 0x2219, .end = 0x2219, .idx = -8432 },
  { .start = 0x2500, .end = 0x2502, .idx = -9174 },
  { .start = 0x250c, .end = 0x251c, .idx = -9183 },
  { .start = 0x2524, .end = 0x2524, .idx = -9190 },
  { .start = 0x252c, .end = 0x252c, .idx = -9197 },
  { .start = 0x2534, .end = 0x2534, .idx = -9204 },
  { .start = 0x253c, .end = 0x253c, .idx = -9211 },
  { .start = 0x2550, .end = 0x256c, .idx = -9230 },
  { .start = 0x2580, .end = 0x2593, .idx = -9249 },
  { .start = 0x25a0, .end = 0x25a0, .idx = -9261 },
  { .start = 0xffff, .end = 0xffff, .idx =     0 }
};

/* Table accessed through above index table.  It can be generated using:

   cat .../unix/mappings/vendors/micsft/pc/cp775.txt |
   awk '/^0x/ { if (NF > 2) print $2, $1; }' | perl gaptab.pl

   where gaptab.pl is the file in this directory.
 */
static const char from_ucs4[] =
{
  '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
  '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
  '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
  '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f',
  '\x20', '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27',
  '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f',
  '\x30', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37',
  '\x38', '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x3e', '\x3f',
  '\x40', '\x41', '\x42', '\x43', '\x44', '\x45', '\x46', '\x47',
  '\x48', '\x49', '\x4a', '\x4b', '\x4c', '\x4d', '\x4e', '\x4f',
  '\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57',
  '\x58', '\x59', '\x5a', '\x5b', '\x5c', '\x5d', '\x5e', '\x5f',
  '\x60', '\x61', '\x62', '\x63', '\x64', '\x65', '\x66', '\x67',
  '\x68', '\x69', '\x6a', '\x6b', '\x6c', '\x6d', '\x6e', '\x6f',
  '\x70', '\x71', '\x72', '\x73', '\x74', '\x75', '\x76', '\x77',
  '\x78', '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e', '\x7f',
  '\xff', '\x00', '\x96', '\x9c', '\x9f', '\x00', '\xa7', '\xf5',
  '\x00', '\xa8', '\x00', '\xae', '\xaa', '\xf0', '\xa9', '\x00',
  '\xf8', '\xf1', '\xfd', '\xfc', '\x00', '\xe6', '\xf4', '\xfa',
  '\x00', '\xfb', '\x00', '\xaf', '\xac', '\xab', '\xf3', '\x00',
  '\x00', '\x00', '\x00', '\x00', '\x8e', '\x8f', '\x92', '\x00',
  '\x00', '\x90', '\xe0', '\x00', '\xe5', '\x99', '\x9e', '\x9d',
  '\x00', '\x00', '\x00', '\x9a', '\x00', '\x00', '\xe1', '\x00',
  '\x00', '\x00', '\x00', '\x84', '\x86', '\x91', '\x00', '\x00',
  '\x82', '\xa2', '\x00', '\xe4', '\x94', '\xf6', '\x9b', '\x00',
  '\x00', '\x00', '\x81', '\x00', '\x00', '\x00', '\xa0', '\x83',
  '\x00', '\x00', '\xb5', '\xd0', '\x80', '\x87', '\x00', '\x00',
  '\x00', '\x00', '\xb6', '\xd1', '\x00', '\x00', '\x00', '\x00',
  '\xed', '\x89', '\x00', '\x00', '\xb8', '\xd3', '\xb7', '\xd2',
  '\x95', '\x85', '\xa1', '\x8c', '\x00', '\x00', '\xbd', '\xd4',
  '\xe8', '\xe9', '\x00', '\x00', '\x00', '\xea', '\xeb', '\x00',
  '\x00', '\x00', '\x00', '\xad', '\x88', '\xe3', '\xe7', '\xee',
  '\xec', '\x00', '\x00', '\x00', '\x00', '\x00', '\xe2', '\x93',
  '\x8a', '\x8b', '\x00', '\x00', '\x97', '\x98', '\x00', '\x00',
  '\x00', '\x00', '\xbe', '\xd5', '\xc7', '\xd7', '\xc6', '\xd6',
  '\x00', '\x00', '\x00', '\x00', '\x00', '\x8d', '\xa5', '\xa3',
  '\xa4', '\xcf', '\xd8', '\xef', '\x00', '\x00', '\xf2', '\xa6',
  '\xf7', '\xf9', '\xc4', '\x00', '\xb3', '\xda', '\x00', '\x00',
  '\x00', '\xbf', '\x00', '\x00', '\x00', '\xc0', '\x00', '\x00',
  '\x00', '\xd9', '\x00', '\x00', '\x00', '\xc3', '\xb4', '\xc2',
  '\xc1', '\xc5', '\xcd', '\xba', '\x00', '\x00', '\xc9', '\x00',
  '\x00', '\xbb', '\x00', '\x00', '\xc8', '\x00', '\x00', '\xbc',
  '\x00', '\x00', '\xcc', '\x00', '\x00', '\xb9', '\x00', '\x00',
  '\xcb', '\x00', '\x00', '\xca', '\x00', '\x00', '\xce', '\xdf',
  '\x00', '\x00', '\x00', '\xdc', '\x00', '\x00', '\x00', '\xdb',
  '\x00', '\x00', '\x00', '\xdd', '\x00', '\x00', '\x00', '\xde',
  '\xb0', '\xb1', '\xb2', '\xfe',
};
