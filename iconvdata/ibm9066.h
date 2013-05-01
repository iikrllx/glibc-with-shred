/* Tables for conversion from and to IBM9066.
   Copyright (C) 2005-2013 Free Software Foundation, Inc.
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
  [0x04] = 0x0004, [0x05] = 0x0005, [0x06] = 0x0006, [0x07] = 0x0007,
  [0x08] = 0x0008, [0x09] = 0x0009, [0x0a] = 0x000a, [0x0b] = 0x000b,
  [0x0c] = 0x000c, [0x0d] = 0x000d, [0x0e] = 0x000e, [0x0f] = 0x000f,
  [0x10] = 0x0010, [0x11] = 0x0011, [0x12] = 0x0012, [0x13] = 0x0013,
  [0x14] = 0x0014, [0x15] = 0x0015, [0x16] = 0x0016, [0x17] = 0x0017,
  [0x18] = 0x0018, [0x19] = 0x0019, [0x1a] = 0x001c, [0x1b] = 0x001b,
  [0x1c] = 0x007f, [0x1d] = 0x001d, [0x1e] = 0x001e, [0x1f] = 0x001f,
  [0x20] = 0x0020, [0x21] = 0x0021, [0x22] = 0x0022, [0x23] = 0x0023,
  [0x24] = 0x0024, [0x25] = 0x0025, [0x26] = 0x0026, [0x27] = 0x0027,
  [0x28] = 0x0028, [0x29] = 0x0029, [0x2a] = 0x002a, [0x2b] = 0x002b,
  [0x2c] = 0x002c, [0x2d] = 0x002d, [0x2e] = 0x002e, [0x2f] = 0x002f,
  [0x30] = 0x0030, [0x31] = 0x0031, [0x32] = 0x0032, [0x33] = 0x0033,
  [0x34] = 0x0034, [0x35] = 0x0035, [0x36] = 0x0036, [0x37] = 0x0037,
  [0x38] = 0x0038, [0x39] = 0x0039, [0x3a] = 0x003a, [0x3b] = 0x003b,
  [0x3c] = 0x003c, [0x3d] = 0x003d, [0x3e] = 0x003e, [0x3f] = 0x003f,
  [0x40] = 0x0040, [0x41] = 0x0041, [0x42] = 0x0042, [0x43] = 0x0043,
  [0x44] = 0x0044, [0x45] = 0x0045, [0x46] = 0x0046, [0x47] = 0x0047,
  [0x48] = 0x0048, [0x49] = 0x0049, [0x4a] = 0x004a, [0x4b] = 0x004b,
  [0x4c] = 0x004c, [0x4d] = 0x004d, [0x4e] = 0x004e, [0x4f] = 0x004f,
  [0x50] = 0x0050, [0x51] = 0x0051, [0x52] = 0x0052, [0x53] = 0x0053,
  [0x54] = 0x0054, [0x55] = 0x0055, [0x56] = 0x0056, [0x57] = 0x0057,
  [0x58] = 0x0058, [0x59] = 0x0059, [0x5a] = 0x005a, [0x5b] = 0x005b,
  [0x5c] = 0x005c, [0x5d] = 0x005d, [0x5e] = 0x005e, [0x5f] = 0x005f,
  [0x60] = 0x0060, [0x61] = 0x0061, [0x62] = 0x0062, [0x63] = 0x0063,
  [0x64] = 0x0064, [0x65] = 0x0065, [0x66] = 0x0066, [0x67] = 0x0067,
  [0x68] = 0x0068, [0x69] = 0x0069, [0x6a] = 0x006a, [0x6b] = 0x006b,
  [0x6c] = 0x006c, [0x6d] = 0x006d, [0x6e] = 0x006e, [0x6f] = 0x006f,
  [0x70] = 0x0070, [0x71] = 0x0071, [0x72] = 0x0072, [0x73] = 0x0073,
  [0x74] = 0x0074, [0x75] = 0x0075, [0x76] = 0x0076, [0x77] = 0x0077,
  [0x78] = 0x0078, [0x79] = 0x0079, [0x7a] = 0x007a, [0x7b] = 0x007b,
  [0x7c] = 0x007c, [0x7d] = 0x007d, [0x7e] = 0x007e, [0x7f] = 0x001a,
  [0xa0] = 0x0e48, [0xa1] = 0x0e01, [0xa2] = 0x0e02, [0xa3] = 0x0e03,
  [0xa4] = 0x0e04, [0xa5] = 0x0e05, [0xa6] = 0x0e06, [0xa7] = 0x0e07,
  [0xa8] = 0x0e08, [0xa9] = 0x0e09, [0xaa] = 0x0e0a, [0xab] = 0x0e0b,
  [0xac] = 0x0e0c, [0xad] = 0x0e0d, [0xae] = 0x0e0e, [0xaf] = 0x0e0f,
  [0xb0] = 0x0e10, [0xb1] = 0x0e11, [0xb2] = 0x0e12, [0xb3] = 0x0e13,
  [0xb4] = 0x0e14, [0xb5] = 0x0e15, [0xb6] = 0x0e16, [0xb7] = 0x0e17,
  [0xb8] = 0x0e18, [0xb9] = 0x0e19, [0xba] = 0x0e1a, [0xbb] = 0x0e1b,
  [0xbc] = 0x0e1c, [0xbd] = 0x0e1d, [0xbe] = 0x0e1e, [0xbf] = 0x0e1f,
  [0xc0] = 0x0e20, [0xc1] = 0x0e21, [0xc2] = 0x0e22, [0xc3] = 0x0e23,
  [0xc4] = 0x0e24, [0xc5] = 0x0e25, [0xc6] = 0x0e26, [0xc7] = 0x0e27,
  [0xc8] = 0x0e28, [0xc9] = 0x0e29, [0xca] = 0x0e2a, [0xcb] = 0x0e2b,
  [0xcc] = 0x0e2c, [0xcd] = 0x0e2d, [0xce] = 0x0e2e, [0xcf] = 0x0e2f,
  [0xd0] = 0x0e30, [0xd1] = 0x0e31, [0xd2] = 0x0e32, [0xd3] = 0x0e33,
  [0xd4] = 0x0e34, [0xd5] = 0x0e35, [0xd6] = 0x0e36, [0xd7] = 0x0e37,
  [0xd8] = 0x0e38, [0xd9] = 0x0e39, [0xda] = 0x0e3a, [0xdb] = 0x0e49,
  [0xdc] = 0x0e4a, [0xdd] = 0x0e4b, [0xde] = 0x0e4c, [0xdf] = 0x0e3f,
  [0xe0] = 0x0e40, [0xe1] = 0x0e41, [0xe2] = 0x0e42, [0xe3] = 0x0e43,
  [0xe4] = 0x0e44, [0xe5] = 0x0e45, [0xe6] = 0x0e46, [0xe7] = 0x0e47,
  [0xe8] = 0x0e48, [0xe9] = 0x0e49, [0xea] = 0x0e4a, [0xeb] = 0x0e4b,
  [0xec] = 0x0e4c, [0xed] = 0x0e4d, [0xee] = 0x0e4e, [0xef] = 0x0e4f,
  [0xf0] = 0x0e50, [0xf1] = 0x0e51, [0xf2] = 0x0e52, [0xf3] = 0x0e53,
  [0xf4] = 0x0e54, [0xf5] = 0x0e55, [0xf6] = 0x0e56, [0xf7] = 0x0e57,
  [0xf8] = 0x0e58, [0xf9] = 0x0e59, [0xfa] = 0x0e5a, [0xfb] = 0x0e5b,
  [0xfc] = 0x00a2, [0xfd] = 0x00ac, [0xfe] = 0x00a6, [0xff] = 0x00a0
};

static const struct gap from_idx[] =
{
  { start: 0x0000, end: 0x007f, idx:     0 },
  { start: 0x00a0, end: 0x00ac, idx:   -32 },
  { start: 0x0e01, end: 0x0e5b, idx: -3444 },
  { start: 0xffff, end: 0xffff, idx:     0 }
};

static const char from_ucs4[] =
{
  '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
  '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
  '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17',
  '\x18', '\x19', '\x7f', '\x1b', '\x1a', '\x1d', '\x1e', '\x1f',
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
  '\x78', '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e', '\x1c',
  '\xff', '\x00', '\xfc', '\x00', '\x00', '\x00', '\xfe', '\x00',
  '\x00', '\x00', '\x00', '\x00', '\xfd', '\xa1', '\xa2', '\xa3',
  '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xaa', '\xab',
  '\xac', '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb3',
  '\xb4', '\xb5', '\xb6', '\xb7', '\xb8', '\xb9', '\xba', '\xbb',
  '\xbc', '\xbd', '\xbe', '\xbf', '\xc0', '\xc1', '\xc2', '\xc3',
  '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xca', '\xcb',
  '\xcc', '\xcd', '\xce', '\xcf', '\xd0', '\xd1', '\xd2', '\xd3',
  '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xda', '\x00',
  '\x00', '\x00', '\x00', '\xdf', '\xe0', '\xe1', '\xe2', '\xe3',
  '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xea', '\xeb',
  '\xec', '\xed', '\xee', '\xef', '\xf0', '\xf1', '\xf2', '\xf3',
  '\xf4', '\xf5', '\xf6', '\xf7', '\xf8', '\xf9', '\xfa', '\xfb'
};
