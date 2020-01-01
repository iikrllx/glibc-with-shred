/* Mapping table for IBM1137.
   Copyright (C) 2005-2020 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jiro SEKIBA <sekiba@jp.ibm.com>, 2005.

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
  [0x40] = 0x0020, [0x41] = 0x00a0, [0x42] = 0x0901, [0x43] = 0x0902,
  [0x44] = 0x0903, [0x45] = 0x0905, [0x46] = 0x0906, [0x47] = 0x0907,
  [0x48] = 0x0908, [0x49] = 0x0909, [0x4a] = 0x090a, [0x4b] = 0x002e,
  [0x4c] = 0x003c, [0x4d] = 0x0028, [0x4e] = 0x002b, [0x4f] = 0x007c,
  [0x50] = 0x0026, [0x51] = 0x090b, [0x52] = 0x090c, [0x53] = 0x090d,
  [0x54] = 0x090e, [0x55] = 0x090f, [0x56] = 0x0910, [0x57] = 0x0911,
  [0x58] = 0x0912, [0x59] = 0x0913, [0x5a] = 0x0021, [0x5b] = 0x0024,
  [0x5c] = 0x002a, [0x5d] = 0x0029, [0x5e] = 0x003b, [0x5f] = 0x005e,
  [0x60] = 0x002d, [0x61] = 0x002f, [0x62] = 0x0914, [0x63] = 0x0915,
  [0x64] = 0x0916, [0x65] = 0x0917, [0x66] = 0x0918, [0x67] = 0x0919,
  [0x68] = 0x091a, [0x69] = 0x091b, [0x6a] = 0x091c, [0x6b] = 0x002c,
  [0x6c] = 0x0025, [0x6d] = 0x005f, [0x6e] = 0x003e, [0x6f] = 0x003f,
  [0x70] = 0x091d, [0x71] = 0x091e, [0x72] = 0x091f, [0x73] = 0x0920,
  [0x74] = 0x0921, [0x75] = 0x0922, [0x76] = 0x0923, [0x77] = 0x0924,
  [0x78] = 0x0925, [0x79] = 0x0060, [0x7a] = 0x003a, [0x7b] = 0x0023,
  [0x7c] = 0x0040, [0x7d] = 0x0027, [0x7e] = 0x003d, [0x7f] = 0x0022,
  [0x80] = 0x0926, [0x81] = 0x0061, [0x82] = 0x0062, [0x83] = 0x0063,
  [0x84] = 0x0064, [0x85] = 0x0065, [0x86] = 0x0066, [0x87] = 0x0067,
  [0x88] = 0x0068, [0x89] = 0x0069, [0x8a] = 0x0927, [0x8b] = 0x0928,
  [0x8c] = 0x092a, [0x8d] = 0x092b, [0x8e] = 0x092c, [0x8f] = 0x092d,
  [0x90] = 0x092e, [0x91] = 0x006a, [0x92] = 0x006b, [0x93] = 0x006c,
  [0x94] = 0x006d, [0x95] = 0x006e, [0x96] = 0x006f, [0x97] = 0x0070,
  [0x98] = 0x0071, [0x99] = 0x0072, [0x9a] = 0x092f, [0x9b] = 0x0930,
  [0x9c] = 0x0932, [0x9d] = 0x0933, [0x9e] = 0x0935, [0x9f] = 0x0936,
  [0xa0] = 0x200c, [0xa1] = 0x007e, [0xa2] = 0x0073, [0xa3] = 0x0074,
  [0xa4] = 0x0075, [0xa5] = 0x0076, [0xa6] = 0x0077, [0xa7] = 0x0078,
  [0xa8] = 0x0079, [0xa9] = 0x007a, [0xaa] = 0x0937, [0xab] = 0x0938,
  [0xac] = 0x0939, [0xad] = 0x005b, [0xae] = 0x093c, [0xaf] = 0x093d,
  [0xb0] = 0x093e, [0xb1] = 0x093f, [0xb2] = 0x0940, [0xb3] = 0x0941,
  [0xb4] = 0x0942, [0xb5] = 0x0943, [0xb6] = 0x0944, [0xb7] = 0x0945,
  [0xb8] = 0x0946, [0xb9] = 0x0947, [0xba] = 0x0948, [0xbb] = 0x0949,
  [0xbc] = 0x094a, [0xbd] = 0x005d, [0xbe] = 0x094b, [0xbf] = 0x094c,
  [0xc0] = 0x007b, [0xc1] = 0x0041, [0xc2] = 0x0042, [0xc3] = 0x0043,
  [0xc4] = 0x0044, [0xc5] = 0x0045, [0xc6] = 0x0046, [0xc7] = 0x0047,
  [0xc8] = 0x0048, [0xc9] = 0x0049, [0xca] = 0x094d, [0xcb] = 0x0950,
  [0xcc] = 0x0951, [0xcd] = 0x0952, [0xd0] = 0x007d, [0xd1] = 0x004a,
  [0xd2] = 0x004b, [0xd3] = 0x004c, [0xd4] = 0x004d, [0xd5] = 0x004e,
  [0xd6] = 0x004f, [0xd7] = 0x0050, [0xd8] = 0x0051, [0xd9] = 0x0052,
  [0xda] = 0x0960, [0xdb] = 0x0961, [0xdc] = 0x0962, [0xdd] = 0x0963,
  [0xde] = 0x0964, [0xdf] = 0x0965, [0xe0] = 0x005c, [0xe1] = 0x200d,
  [0xe2] = 0x0053, [0xe3] = 0x0054, [0xe4] = 0x0055, [0xe5] = 0x0056,
  [0xe6] = 0x0057, [0xe7] = 0x0058, [0xe8] = 0x0059, [0xe9] = 0x005a,
  [0xea] = 0x0966, [0xeb] = 0x0967, [0xec] = 0x0968, [0xed] = 0x0969,
  [0xee] = 0x096a, [0xef] = 0x096b, [0xf0] = 0x0030, [0xf1] = 0x0031,
  [0xf2] = 0x0032, [0xf3] = 0x0033, [0xf4] = 0x0034, [0xf5] = 0x0035,
  [0xf6] = 0x0036, [0xf7] = 0x0037, [0xf8] = 0x0038, [0xf9] = 0x0039,
  [0xfa] = 0x096c, [0xfb] = 0x096d, [0xfc] = 0x096e, [0xfd] = 0x096f,
  [0xfe] = 0x0970, [0xff] = 0x009f
};

static const struct gap from_idx[] =
{
  { start: 0x0000, end: 0x00a0, idx:     0 },
  { start: 0x0901, end: 0x0952, idx: -2144 },
  { start: 0x0960, end: 0x0970, idx: -2157 },
  { start: 0x200c, end: 0x200d, idx: -7944 },
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
  '\xe7', '\xe8', '\xe9', '\xad', '\xe0', '\xbd', '\x5f', '\x6d',
  '\x79', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87',
  '\x88', '\x89', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96',
  '\x97', '\x98', '\x99', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6',
  '\xa7', '\xa8', '\xa9', '\xc0', '\x4f', '\xd0', '\xa1', '\x07',
  '\x20', '\x21', '\x22', '\x23', '\x24', '\x15', '\x06', '\x17',
  '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x09', '\x0a', '\x1b',
  '\x30', '\x31', '\x1a', '\x33', '\x34', '\x35', '\x36', '\x08',
  '\x38', '\x39', '\x3a', '\x3b', '\x04', '\x14', '\x3e', '\xff',
  '\x41', '\x42', '\x43', '\x44', '\x00', '\x45', '\x46', '\x47',
  '\x48', '\x49', '\x4a', '\x51', '\x52', '\x53', '\x54', '\x55',
  '\x56', '\x57', '\x58', '\x59', '\x62', '\x63', '\x64', '\x65',
  '\x66', '\x67', '\x68', '\x69', '\x6a', '\x70', '\x71', '\x72',
  '\x73', '\x74', '\x75', '\x76', '\x77', '\x78', '\x80', '\x8a',
  '\x8b', '\x00', '\x8c', '\x8d', '\x8e', '\x8f', '\x90', '\x9a',
  '\x9b', '\x00', '\x9c', '\x9d', '\x00', '\x9e', '\x9f', '\xaa',
  '\xab', '\xac', '\x00', '\x00', '\xae', '\xaf', '\xb0', '\xb1',
  '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7', '\xb8', '\xb9',
  '\xba', '\xbb', '\xbc', '\xbe', '\xbf', '\xca', '\x00', '\x00',
  '\xcb', '\xcc', '\xcd', '\xda', '\xdb', '\xdc', '\xdd', '\xde',
  '\xdf', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef', '\xfa',
  '\xfb', '\xfc', '\xfd', '\xfe', '\xa0', '\xe1'
};
