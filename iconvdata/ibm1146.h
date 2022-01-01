/* Tables for conversion from and to IBM1146.
   Copyright (C) 2005-2022 Free Software Foundation, Inc.
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

#include <stdint.h>

static const uint32_t to_ucs4[256] =
{
  [0x00] = 0x0000, [0x01] = 0x0001, [0x02] = 0x0002, [0x03] = 0x0003,
  [0x04] = 0x009c, [0x05] = 0x0009, [0x06] = 0x0086, [0x07] = 0x007f,
  [0x08] = 0x0097, [0x09] = 0x008d, [0x0a] = 0x008e, [0x0b] = 0x000b,
  [0x0c] = 0x000c, [0x0d] = 0x000d, [0x0e] = 0x000e, [0x0f] = 0x000f,
  [0x10] = 0x0010, [0x11] = 0x0011, [0x12] = 0x0012, [0x13] = 0x0013,
  [0x14] = 0x009d, [0x15] = 0x0085, [0x16] = 0x0008, [0x17] = 0x0087,
  [0x18] = 0x0018, [0x19] = 0x0019, [0x1a] = 0x0092, [0x1b] = 0x008f,
  [0x1c] = 0x001c, [0x1d] = 0x001d, [0x1e] = 0x001e, [0x1f] = 0x001f,
  [0x20] = 0x0080, [0x21] = 0x0081, [0x22] = 0x0082, [0x23] = 0x0083,
  [0x24] = 0x0084, [0x25] = 0x000a, [0x26] = 0x0017, [0x27] = 0x001b,
  [0x28] = 0x0088, [0x29] = 0x0089, [0x2a] = 0x008a, [0x2b] = 0x008b,
  [0x2c] = 0x008c, [0x2d] = 0x0005, [0x2e] = 0x0006, [0x2f] = 0x0007,
  [0x30] = 0x0090, [0x31] = 0x0091, [0x32] = 0x0016, [0x33] = 0x0093,
  [0x34] = 0x0094, [0x35] = 0x0095, [0x36] = 0x0096, [0x37] = 0x0004,
  [0x38] = 0x0098, [0x39] = 0x0099, [0x3a] = 0x009a, [0x3b] = 0x009b,
  [0x3c] = 0x0014, [0x3d] = 0x0015, [0x3e] = 0x009e, [0x3f] = 0x001a,
  [0x40] = 0x0020, [0x41] = 0x00a0, [0x42] = 0x00e2, [0x43] = 0x00e4,
  [0x44] = 0x00e0, [0x45] = 0x00e1, [0x46] = 0x00e3, [0x47] = 0x00e5,
  [0x48] = 0x00e7, [0x49] = 0x00f1, [0x4a] = 0x0024, [0x4b] = 0x002e,
  [0x4c] = 0x003c, [0x4d] = 0x0028, [0x4e] = 0x002b, [0x4f] = 0x007c,
  [0x50] = 0x0026, [0x51] = 0x00e9, [0x52] = 0x00ea, [0x53] = 0x00eb,
  [0x54] = 0x00e8, [0x55] = 0x00ed, [0x56] = 0x00ee, [0x57] = 0x00ef,
  [0x58] = 0x00ec, [0x59] = 0x00df, [0x5a] = 0x0021, [0x5b] = 0x00a3,
  [0x5c] = 0x002a, [0x5d] = 0x0029, [0x5e] = 0x003b, [0x5f] = 0x00ac,
  [0x60] = 0x002d, [0x61] = 0x002f, [0x62] = 0x00c2, [0x63] = 0x00c4,
  [0x64] = 0x00c0, [0x65] = 0x00c1, [0x66] = 0x00c3, [0x67] = 0x00c5,
  [0x68] = 0x00c7, [0x69] = 0x00d1, [0x6a] = 0x00a6, [0x6b] = 0x002c,
  [0x6c] = 0x0025, [0x6d] = 0x005f, [0x6e] = 0x003e, [0x6f] = 0x003f,
  [0x70] = 0x00f8, [0x71] = 0x00c9, [0x72] = 0x00ca, [0x73] = 0x00cb,
  [0x74] = 0x00c8, [0x75] = 0x00cd, [0x76] = 0x00ce, [0x77] = 0x00cf,
  [0x78] = 0x00cc, [0x79] = 0x0060, [0x7a] = 0x003a, [0x7b] = 0x0023,
  [0x7c] = 0x0040, [0x7d] = 0x0027, [0x7e] = 0x003d, [0x7f] = 0x0022,
  [0x80] = 0x00d8, [0x81] = 0x0061, [0x82] = 0x0062, [0x83] = 0x0063,
  [0x84] = 0x0064, [0x85] = 0x0065, [0x86] = 0x0066, [0x87] = 0x0067,
  [0x88] = 0x0068, [0x89] = 0x0069, [0x8a] = 0x00ab, [0x8b] = 0x00bb,
  [0x8c] = 0x00f0, [0x8d] = 0x00fd, [0x8e] = 0x00fe, [0x8f] = 0x00b1,
  [0x90] = 0x00b0, [0x91] = 0x006a, [0x92] = 0x006b, [0x93] = 0x006c,
  [0x94] = 0x006d, [0x95] = 0x006e, [0x96] = 0x006f, [0x97] = 0x0070,
  [0x98] = 0x0071, [0x99] = 0x0072, [0x9a] = 0x00aa, [0x9b] = 0x00ba,
  [0x9c] = 0x00e6, [0x9d] = 0x00b8, [0x9e] = 0x00c6, [0x9f] = 0x20ac,
  [0xa0] = 0x00b5, [0xa1] = 0x00af, [0xa2] = 0x0073, [0xa3] = 0x0074,
  [0xa4] = 0x0075, [0xa5] = 0x0076, [0xa6] = 0x0077, [0xa7] = 0x0078,
  [0xa8] = 0x0079, [0xa9] = 0x007a, [0xaa] = 0x00a1, [0xab] = 0x00bf,
  [0xac] = 0x00d0, [0xad] = 0x00dd, [0xae] = 0x00de, [0xaf] = 0x00ae,
  [0xb0] = 0x00a2, [0xb1] = 0x005b, [0xb2] = 0x00a5, [0xb3] = 0x00b7,
  [0xb4] = 0x00a9, [0xb5] = 0x00a7, [0xb6] = 0x00b6, [0xb7] = 0x00bc,
  [0xb8] = 0x00bd, [0xb9] = 0x00be, [0xba] = 0x005e, [0xbb] = 0x005d,
  [0xbc] = 0x007e, [0xbd] = 0x00a8, [0xbe] = 0x00b4, [0xbf] = 0x00d7,
  [0xc0] = 0x007b, [0xc1] = 0x0041, [0xc2] = 0x0042, [0xc3] = 0x0043,
  [0xc4] = 0x0044, [0xc5] = 0x0045, [0xc6] = 0x0046, [0xc7] = 0x0047,
  [0xc8] = 0x0048, [0xc9] = 0x0049, [0xca] = 0x00ad, [0xcb] = 0x00f4,
  [0xcc] = 0x00f6, [0xcd] = 0x00f2, [0xce] = 0x00f3, [0xcf] = 0x00f5,
  [0xd0] = 0x007d, [0xd1] = 0x004a, [0xd2] = 0x004b, [0xd3] = 0x004c,
  [0xd4] = 0x004d, [0xd5] = 0x004e, [0xd6] = 0x004f, [0xd7] = 0x0050,
  [0xd8] = 0x0051, [0xd9] = 0x0052, [0xda] = 0x00b9, [0xdb] = 0x00fb,
  [0xdc] = 0x00fc, [0xdd] = 0x00f9, [0xde] = 0x00fa, [0xdf] = 0x00ff,
  [0xe0] = 0x005c, [0xe1] = 0x00f7, [0xe2] = 0x0053, [0xe3] = 0x0054,
  [0xe4] = 0x0055, [0xe5] = 0x0056, [0xe6] = 0x0057, [0xe7] = 0x0058,
  [0xe8] = 0x0059, [0xe9] = 0x005a, [0xea] = 0x00b2, [0xeb] = 0x00d4,
  [0xec] = 0x00d6, [0xed] = 0x00d2, [0xee] = 0x00d3, [0xef] = 0x00d5,
  [0xf0] = 0x0030, [0xf1] = 0x0031, [0xf2] = 0x0032, [0xf3] = 0x0033,
  [0xf4] = 0x0034, [0xf5] = 0x0035, [0xf6] = 0x0036, [0xf7] = 0x0037,
  [0xf8] = 0x0038, [0xf9] = 0x0039, [0xfa] = 0x00b3, [0xfb] = 0x00db,
  [0xfc] = 0x00dc, [0xfd] = 0x00d9, [0xfe] = 0x00da, [0xff] = 0x009f
};

static const struct gap from_idx[] =
{
  { start: 0x0000, end: 0x00ff, idx:     0 },
  { start: 0x203e, end: 0x203e, idx: -7998 },
  { start: 0x20ac, end: 0x20ac, idx: -8107 },
  { start: 0xffff, end: 0xffff, idx:     0 }
};

static const char from_ucs4[] =
{
  '\x00', '\x01', '\x02', '\x03', '\x37', '\x2d', '\x2e', '\x2f',
  '\x16', '\x05', '\x25', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
  '\x10', '\x11', '\x12', '\x13', '\x3c', '\x3d', '\x32', '\x26',
  '\x18', '\x19', '\x3f', '\x27', '\x1c', '\x1d', '\x1e', '\x1f',
  '\x40', '\x5a', '\x7f', '\x7b', '\x4a', '\x6c', '\x50', '\x7d',
  '\x4d', '\x5d', '\x5c', '\x4e', '\x6b', '\x60', '\x4b', '\x61',
  '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7',
  '\xf8', '\xf9', '\x7a', '\x5e', '\x4c', '\x7e', '\x6e', '\x6f',
  '\x7c', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7',
  '\xc8', '\xc9', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6',
  '\xd7', '\xd8', '\xd9', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6',
  '\xe7', '\xe8', '\xe9', '\xb1', '\xe0', '\xbb', '\xba', '\x6d',
  '\x79', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
  '\x88', '\x89', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96',
  '\x97', '\x98', '\x99', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6',
  '\xa7', '\xa8', '\xa9', '\xc0', '\x4f', '\xd0', '\xbc', '\x07',
  '\x20', '\x21', '\x22', '\x23', '\x24', '\x15', '\x06', '\x17',
  '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x09', '\x0a', '\x1b',
  '\x30', '\x31', '\x1a', '\x33', '\x34', '\x35', '\x36', '\x08',
  '\x38', '\x39', '\x3a', '\x3b', '\x04', '\x14', '\x3e', '\xff',
  '\x41', '\xaa', '\xb0', '\x5b', '\x00', '\xb2', '\x6a', '\xb5',
  '\xbd', '\xb4', '\x9a', '\x8a', '\x5f', '\xca', '\xaf', '\xa1',
  '\x90', '\x8f', '\xea', '\xfa', '\xbe', '\xa0', '\xb6', '\xb3',
  '\x9d', '\xda', '\x9b', '\x8b', '\xb7', '\xb8', '\xb9', '\xab',
  '\x64', '\x65', '\x62', '\x66', '\x63', '\x67', '\x9e', '\x68',
  '\x74', '\x71', '\x72', '\x73', '\x78', '\x75', '\x76', '\x77',
  '\xac', '\x69', '\xed', '\xee', '\xeb', '\xef', '\xec', '\xbf',
  '\x80', '\xfd', '\xfe', '\xfb', '\xfc', '\xad', '\xae', '\x59',
  '\x44', '\x45', '\x42', '\x46', '\x43', '\x47', '\x9c', '\x48',
  '\x54', '\x51', '\x52', '\x53', '\x58', '\x55', '\x56', '\x57',
  '\x8c', '\x49', '\xcd', '\xce', '\xcb', '\xcf', '\xcc', '\xe1',
  '\x70', '\xdd', '\xde', '\xdb', '\xdc', '\x8d', '\x8e', '\xdf',
  '\xa1', '\x9f'
};
