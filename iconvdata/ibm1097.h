/* Tables for conversion from and to IBM1097.
   Copyright (C) 2005-2015 Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

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
  [0x40] = 0x0020, [0x41] = 0x00a0, [0x42] = 0x060c, [0x43] = 0x064b,
  [0x44] = 0xfe81, [0x45] = 0xfe82, [0x46] = 0xf8fa, [0x47] = 0xfe8d,
  [0x48] = 0xfe8e, [0x49] = 0xf8fb, [0x4a] = 0x00a4, [0x4b] = 0x002e,
  [0x4c] = 0x003c, [0x4d] = 0x0028, [0x4e] = 0x002b, [0x4f] = 0x007c,
  [0x50] = 0x0026, [0x51] = 0xfe80, [0x52] = 0xfe83, [0x53] = 0xfe84,
  [0x54] = 0xf8f9, [0x55] = 0xfe85, [0x56] = 0xfe8b, [0x57] = 0xfe8f,
  [0x58] = 0xfe91, [0x59] = 0xfb56, [0x5a] = 0x0021, [0x5b] = 0x0024,
  [0x5c] = 0x002a, [0x5d] = 0x0029, [0x5e] = 0x003b, [0x5f] = 0x00ac,
  [0x60] = 0x002d, [0x61] = 0x002f, [0x62] = 0xfb58, [0x63] = 0xfe95,
  [0x64] = 0xfe97, [0x65] = 0xfe99, [0x66] = 0xfe9b, [0x67] = 0xfe9d,
  [0x68] = 0xfe9f, [0x69] = 0xfb7a, [0x6a] = 0x061b, [0x6b] = 0x002c,
  [0x6c] = 0x0025, [0x6d] = 0x005f, [0x6e] = 0x003e, [0x6f] = 0x003f,
  [0x70] = 0xfb7c, [0x71] = 0xfea1, [0x72] = 0xfea3, [0x73] = 0xfea5,
  [0x74] = 0xfea7, [0x75] = 0xfea9, [0x76] = 0xfeab, [0x77] = 0xfead,
  [0x78] = 0xfeaf, [0x79] = 0x0060, [0x7a] = 0x003a, [0x7b] = 0x0023,
  [0x7c] = 0x0040, [0x7d] = 0x0027, [0x7e] = 0x003d, [0x7f] = 0x0022,
  [0x80] = 0xfb8a, [0x81] = 0x0061, [0x82] = 0x0062, [0x83] = 0x0063,
  [0x84] = 0x0064, [0x85] = 0x0065, [0x86] = 0x0066, [0x87] = 0x0067,
  [0x88] = 0x0068, [0x89] = 0x0069, [0x8a] = 0x00ab, [0x8b] = 0x00bb,
  [0x8c] = 0xfeb1, [0x8d] = 0xfeb3, [0x8e] = 0xfeb5, [0x8f] = 0xfeb7,
  [0x90] = 0xfeb9, [0x91] = 0x006a, [0x92] = 0x006b, [0x93] = 0x006c,
  [0x94] = 0x006d, [0x95] = 0x006e, [0x96] = 0x006f, [0x97] = 0x0070,
  [0x98] = 0x0071, [0x99] = 0x0072, [0x9a] = 0xfebb, [0x9b] = 0xfebd,
  [0x9c] = 0xfebf, [0x9d] = 0xfec1, [0x9e] = 0xfec3, [0x9f] = 0xfec5,
  [0xa0] = 0xfec7, [0xa1] = 0x007e, [0xa2] = 0x0073, [0xa3] = 0x0074,
  [0xa4] = 0x0075, [0xa5] = 0x0076, [0xa6] = 0x0077, [0xa7] = 0x0078,
  [0xa8] = 0x0079, [0xa9] = 0x007a, [0xaa] = 0xfec9, [0xab] = 0xfeca,
  [0xac] = 0xfecb, [0xad] = 0xfecc, [0xae] = 0xfecd, [0xaf] = 0xfece,
  [0xb0] = 0xfecf, [0xb1] = 0xfed0, [0xb2] = 0xfed1, [0xb3] = 0xfed3,
  [0xb4] = 0xfed5, [0xb5] = 0xfed7, [0xb6] = 0xfb8e, [0xb7] = 0xfedb,
  [0xb8] = 0xfb92, [0xb9] = 0xfb94, [0xba] = 0x005b, [0xbb] = 0x005d,
  [0xbc] = 0xfedd, [0xbd] = 0xfedf, [0xbe] = 0xfee1, [0xbf] = 0x00d7,
  [0xc0] = 0x007b, [0xc1] = 0x0041, [0xc2] = 0x0042, [0xc3] = 0x0043,
  [0xc4] = 0x0044, [0xc5] = 0x0045, [0xc6] = 0x0046, [0xc7] = 0x0047,
  [0xc8] = 0x0048, [0xc9] = 0x0049, [0xca] = 0x00ad, [0xcb] = 0xfee3,
  [0xcc] = 0xfee5, [0xcd] = 0xfee7, [0xce] = 0xfeed, [0xcf] = 0xfee9,
  [0xd0] = 0x007d, [0xd1] = 0x004a, [0xd2] = 0x004b, [0xd3] = 0x004c,
  [0xd4] = 0x004d, [0xd5] = 0x004e, [0xd6] = 0x004f, [0xd7] = 0x0050,
  [0xd8] = 0x0051, [0xd9] = 0x0052, [0xda] = 0xfeeb, [0xdb] = 0xfeec,
  [0xdc] = 0xfba4, [0xdd] = 0xfbfc, [0xde] = 0xfbfd, [0xdf] = 0xfbfe,
  [0xe0] = 0x005c, [0xe1] = 0x061f, [0xe2] = 0x0053, [0xe3] = 0x0054,
  [0xe4] = 0x0055, [0xe5] = 0x0056, [0xe6] = 0x0057, [0xe7] = 0x0058,
  [0xe8] = 0x0059, [0xe9] = 0x005a, [0xea] = 0x0640, [0xeb] = 0x06f0,
  [0xec] = 0x06f1, [0xed] = 0x06f2, [0xee] = 0x06f3, [0xef] = 0x06f4,
  [0xf0] = 0x0030, [0xf1] = 0x0031, [0xf2] = 0x0032, [0xf3] = 0x0033,
  [0xf4] = 0x0034, [0xf5] = 0x0035, [0xf6] = 0x0036, [0xf7] = 0x0037,
  [0xf8] = 0x0038, [0xf9] = 0x0039, [0xfa] = 0x06f5, [0xfb] = 0x06f6,
  [0xfc] = 0x06f7, [0xfd] = 0x06f8, [0xfe] = 0x06f9, [0xff] = 0x009f
};

static const struct gap from_idx[] =
{
  { start: 0x0000, end: 0x00a4, idx:     0 },
  { start: 0x00ab, end: 0x00ad, idx:    -6 },
  { start: 0x00bb, end: 0x00bb, idx:   -19 },
  { start: 0x00d7, end: 0x00d7, idx:   -46 },
  { start: 0x060c, end: 0x060c, idx: -1378 },
  { start: 0x061b, end: 0x064b, idx: -1392 },
  { start: 0x0660, end: 0x066d, idx: -1412 },
  { start: 0x06f0, end: 0x06f9, idx: -1542 },
  { start: 0xf8f9, end: 0xf8fb, idx: -63493 },
  { start: 0xfb56, end: 0xfb58, idx: -64095 },
  { start: 0xfb7a, end: 0xfb7c, idx: -64128 },
  { start: 0xfb8a, end: 0xfb94, idx: -64141 },
  { start: 0xfba4, end: 0xfba4, idx: -64156 },
  { start: 0xfbfc, end: 0xfbfe, idx: -64243 },
  { start: 0xfe80, end: 0xfeee, idx: -64884 },
  { start: 0xffff, end: 0xffff, idx:     0 }
};

static const char from_ucs4[] =
{
  '\x00', '\x01', '\x02', '\x03', '\x37', '\x2d', '\x2e', '\x2f',
  '\x16', '\x05', '\x25', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
  '\x10', '\x11', '\x12', '\x13', '\x3c', '\x3d', '\x32', '\x26',
  '\x18', '\x19', '\x3f', '\x27', '\x1c', '\x1d', '\x1e', '\x1f',
  '\x40', '\x5a', '\x7f', '\x7b', '\x5b', '\x6c', '\x50', '\x7d',
  '\x4d', '\x5d', '\x5c', '\x4e', '\x6b', '\x60', '\x4b', '\x61',
  '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7',
  '\xf8', '\xf9', '\x7a', '\x5e', '\x4c', '\x7e', '\x6e', '\x6f',
  '\x7c', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7',
  '\xc8', '\xc9', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6',
  '\xd7', '\xd8', '\xd9', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6',
  '\xe7', '\xe8', '\xe9', '\xba', '\xe0', '\xbb', '\x00', '\x6d',
  '\x79', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
  '\x88', '\x89', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96',
  '\x97', '\x98', '\x99', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6',
  '\xa7', '\xa8', '\xa9', '\xc0', '\x4f', '\xd0', '\xa1', '\x07',
  '\x20', '\x21', '\x22', '\x23', '\x24', '\x15', '\x06', '\x17',
  '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x09', '\x0a', '\x1b',
  '\x30', '\x31', '\x1a', '\x33', '\x34', '\x35', '\x36', '\x08',
  '\x38', '\x39', '\x3a', '\x3b', '\x04', '\x14', '\x3e', '\xff',
  '\x41', '\x00', '\x00', '\x00', '\x4a', '\x8a', '\x5f', '\xca',
  '\x8b', '\xbf', '\x42', '\x6a', '\x00', '\x00', '\x00', '\xe1',
  '\x00', '\x51', '\x44', '\x52', '\x55', '\x00', '\x00', '\x47',
  '\x57', '\x00', '\x63', '\x65', '\x67', '\x71', '\x73', '\x75',
  '\x76', '\x77', '\x78', '\x8c', '\x8e', '\x90', '\x9b', '\x00',
  '\x00', '\xaa', '\xae', '\x00', '\x00', '\x00', '\x00', '\x00',
  '\xea', '\xb2', '\xb4', '\x00', '\xbc', '\xbe', '\xcc', '\xcf',
  '\xce', '\x00', '\x00', '\x43', '\xeb', '\xec', '\xed', '\xee',
  '\xef', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\x6c', '\x6b',
  '\x4b', '\x5c', '\xeb', '\xec', '\xed', '\xee', '\xef', '\xfa',
  '\xfb', '\xfc', '\xfd', '\xfe', '\x54', '\x46', '\x49', '\x59',
  '\x00', '\x62', '\x69', '\x00', '\x70', '\x80', '\x00', '\x00',
  '\x00', '\xb6', '\x00', '\x00', '\x00', '\xb8', '\x00', '\xb9',
  '\xdc', '\xdd', '\xde', '\xdf', '\x51', '\x44', '\x45', '\x52',
  '\x53', '\x55', '\x55', '\x00', '\x00', '\x00', '\x00', '\x56',
  '\x56', '\x47', '\x48', '\x57', '\x57', '\x58', '\x58', '\x00',
  '\x00', '\x63', '\x63', '\x64', '\x64', '\x65', '\x65', '\x66',
  '\x66', '\x67', '\x67', '\x68', '\x68', '\x71', '\x71', '\x72',
  '\x72', '\x73', '\x73', '\x74', '\x74', '\x75', '\x75', '\x76',
  '\x76', '\x77', '\x77', '\x78', '\x78', '\x8c', '\x8c', '\x8d',
  '\x8d', '\x8e', '\x8e', '\x8f', '\x8f', '\x90', '\x90', '\x9a',
  '\x9a', '\x9b', '\x9b', '\x9c', '\x9c', '\x9d', '\x9d', '\x9e',
  '\x9e', '\x9f', '\x9f', '\xa0', '\xa0', '\xaa', '\xab', '\xac',
  '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb2', '\xb3',
  '\xb3', '\xb4', '\xb4', '\xb5', '\xb5', '\x00', '\x00', '\xb7',
  '\xb7', '\xbc', '\xbc', '\xbd', '\xbd', '\xbe', '\xbe', '\xcb',
  '\xcb', '\xcc', '\xcc', '\xcd', '\xcd', '\xcf', '\xcf', '\xda',
  '\xdb', '\xce', '\xce'
};
