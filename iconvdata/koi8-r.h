static const wchar_t to_ucs4[256] = {
  [0x01] = 0x0001,
  [0x02] = 0x0002,
  [0x03] = 0x0003,
  [0x04] = 0x0004,
  [0x05] = 0x0005,
  [0x06] = 0x0006,
  [0x07] = 0x0007,
  [0x08] = 0x0008,
  [0x09] = 0x0009,
  [0x0A] = 0x000A,
  [0x0B] = 0x000B,
  [0x0C] = 0x000C,
  [0x0D] = 0x000D,
  [0x0E] = 0x000E,
  [0x0F] = 0x000F,
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
  [0x1A] = 0x001A,
  [0x1B] = 0x001B,
  [0x1C] = 0x001C,
  [0x1D] = 0x001D,
  [0x1E] = 0x001E,
  [0x1F] = 0x001F,
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
  [0x2A] = 0x002A,
  [0x2B] = 0x002B,
  [0x2C] = 0x002C,
  [0x2D] = 0x002D,
  [0x2E] = 0x002E,
  [0x2F] = 0x002F,
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
  [0x3A] = 0x003A,
  [0x3B] = 0x003B,
  [0x3C] = 0x003C,
  [0x3D] = 0x003D,
  [0x3E] = 0x003E,
  [0x3F] = 0x003F,
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
  [0x4A] = 0x004A,
  [0x4B] = 0x004B,
  [0x4C] = 0x004C,
  [0x4D] = 0x004D,
  [0x4E] = 0x004E,
  [0x4F] = 0x004F,
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
  [0x5A] = 0x005A,
  [0x5B] = 0x005B,
  [0x5C] = 0x005C,
  [0x5D] = 0x005D,
  [0x5E] = 0x005E,
  [0x5F] = 0x005F,
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
  [0x6A] = 0x006A,
  [0x6B] = 0x006B,
  [0x6C] = 0x006C,
  [0x6D] = 0x006D,
  [0x6E] = 0x006E,
  [0x6F] = 0x006F,
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
  [0x7A] = 0x007A,
  [0x7B] = 0x007B,
  [0x7C] = 0x007C,
  [0x7D] = 0x007D,
  [0x7E] = 0x007E,
  [0x7F] = 0x007F,
  [0x80] = 0x2500,
  [0x81] = 0x2502,
  [0x82] = 0x250C,
  [0x83] = 0x2510,
  [0x84] = 0x2514,
  [0x85] = 0x2518,
  [0x86] = 0x251C,
  [0x87] = 0x2524,
  [0x88] = 0x252C,
  [0x89] = 0x2534,
  [0x8A] = 0x253C,
  [0x8B] = 0x2580,
  [0x8C] = 0x2584,
  [0x8D] = 0x2588,
  [0x8E] = 0x258C,
  [0x8F] = 0x2590,
  [0x90] = 0x2591,
  [0x91] = 0x2592,
  [0x92] = 0x2593,
  [0x93] = 0x2320,
  [0x94] = 0x25A0,
  [0x95] = 0x2022,
  [0x96] = 0x221A,
  [0x97] = 0x2248,
  [0x98] = 0x2264,
  [0x99] = 0x2265,
  [0x9A] = 0x00A0,
  [0x9B] = 0x2321,
  [0x9C] = 0x00B0,
  [0x9D] = 0x00B2,
  [0x9E] = 0x00B7,
  [0x9F] = 0x00F7,
  [0xA0] = 0x2550,
  [0xA1] = 0x2551,
  [0xA2] = 0x2552,
  [0xA3] = 0x0451,
  [0xA4] = 0x2553,
  [0xA5] = 0x2554,
  [0xA6] = 0x2555,
  [0xA7] = 0x2556,
  [0xA8] = 0x2557,
  [0xA9] = 0x2558,
  [0xAA] = 0x2559,
  [0xAB] = 0x255A,
  [0xAC] = 0x255B,
  [0xAD] = 0x255C,
  [0xAE] = 0x255D,
  [0xAF] = 0x255E,
  [0xB0] = 0x255F,
  [0xB1] = 0x2560,
  [0xB2] = 0x2561,
  [0xB3] = 0x0401,
  [0xB4] = 0x2562,
  [0xB5] = 0x2563,
  [0xB6] = 0x2564,
  [0xB7] = 0x2565,
  [0xB8] = 0x2566,
  [0xB9] = 0x2567,
  [0xBA] = 0x2568,
  [0xBB] = 0x2569,
  [0xBC] = 0x256A,
  [0xBD] = 0x256B,
  [0xBE] = 0x256C,
  [0xBF] = 0x00A9,
  [0xC0] = 0x044E,
  [0xC1] = 0x0430,
  [0xC2] = 0x0431,
  [0xC3] = 0x0446,
  [0xC4] = 0x0434,
  [0xC5] = 0x0435,
  [0xC6] = 0x0444,
  [0xC7] = 0x0433,
  [0xC8] = 0x0445,
  [0xC9] = 0x0438,
  [0xCA] = 0x0439,
  [0xCB] = 0x043A,
  [0xCC] = 0x043B,
  [0xCD] = 0x043C,
  [0xCE] = 0x043D,
  [0xCF] = 0x043E,
  [0xD0] = 0x043F,
  [0xD1] = 0x044F,
  [0xD2] = 0x0440,
  [0xD3] = 0x0441,
  [0xD4] = 0x0442,
  [0xD5] = 0x0443,
  [0xD6] = 0x0436,
  [0xD7] = 0x0432,
  [0xD8] = 0x044C,
  [0xD9] = 0x044B,
  [0xDA] = 0x0437,
  [0xDB] = 0x0448,
  [0xDC] = 0x044D,
  [0xDD] = 0x0449,
  [0xDE] = 0x0447,
  [0xDF] = 0x044A,
  [0xE0] = 0x042E,
  [0xE1] = 0x0410,
  [0xE2] = 0x0411,
  [0xE3] = 0x0426,
  [0xE4] = 0x0414,
  [0xE5] = 0x0415,
  [0xE6] = 0x0424,
  [0xE7] = 0x0413,
  [0xE8] = 0x0425,
  [0xE9] = 0x0418,
  [0xEA] = 0x0419,
  [0xEB] = 0x041A,
  [0xEC] = 0x041B,
  [0xED] = 0x041C,
  [0xEE] = 0x041D,
  [0xEF] = 0x041E,
  [0xF0] = 0x041F,
  [0xF1] = 0x042F,
  [0xF2] = 0x0420,
  [0xF3] = 0x0421,
  [0xF4] = 0x0422,
  [0xF5] = 0x0423,
  [0xF6] = 0x0416,
  [0xF7] = 0x0412,
  [0xF8] = 0x042C,
  [0xF9] = 0x042B,
  [0xFA] = 0x0417,
  [0xFB] = 0x0428,
  [0xFC] = 0x042D,
  [0xFD] = 0x0429,
  [0xFE] = 0x0427,
  [0xFF] = 0x042A,
};
static struct gap from_idx[] = {
  { start: 000000, end: 0x007f, idx:     0 },
  { start: 0x00a0, end: 0x00a0, idx:   -32 },
  { start: 0x00a9, end: 0x00a9, idx:   -40 },
  { start: 0x00b0, end: 0x00b7, idx:   -46 },
  { start: 0x00f7, end: 0x00f7, idx:  -109 },
  { start: 0x0401, end: 0x0401, idx:  -886 },
  { start: 0x0410, end: 0x0451, idx:  -900 },
  { start: 0x2022, end: 0x2022, idx: -8020 },
  { start: 0x221a, end: 0x221a, idx: -8523 },
  { start: 0x2248, end: 0x2248, idx: -8568 },
  { start: 0x2264, end: 0x2265, idx: -8595 },
  { start: 0x2320, end: 0x2321, idx: -8781 },
  { start: 0x2500, end: 0x2502, idx: -9259 },
  { start: 0x250c, end: 0x251c, idx: -9268 },
  { start: 0x2524, end: 0x2524, idx: -9275 },
  { start: 0x252c, end: 0x252c, idx: -9282 },
  { start: 0x2534, end: 0x2534, idx: -9289 },
  { start: 0x253c, end: 0x253c, idx: -9296 },
  { start: 0x2550, end: 0x256c, idx: -9315 },
  { start: 0x2580, end: 0x2593, idx: -9334 },
  { start: 0x25a0, end: 0x25a0, idx: -9346 },
  { start: 0xffff, end: 0xffff, idx:     0 }
};
static const char from_ucs4[] = {

  '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08',
  '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10',
  '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18',
  '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20',
  '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27', '\x28',
  '\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f', '\x30',
  '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37', '\x38',
  '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x3e', '\x3f', '\x40',
  '\x41', '\x42', '\x43', '\x44', '\x45', '\x46', '\x47', '\x48',
  '\x49', '\x4a', '\x4b', '\x4c', '\x4d', '\x4e', '\x4f', '\x50',
  '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57', '\x58',
  '\x59', '\x5a', '\x5b', '\x5c', '\x5d', '\x5e', '\x5f', '\x60',
  '\x61', '\x62', '\x63', '\x64', '\x65', '\x66', '\x67', '\x68',
  '\x69', '\x6a', '\x6b', '\x6c', '\x6d', '\x6e', '\x6f', '\x70',
  '\x71', '\x72', '\x73', '\x74', '\x75', '\x76', '\x77', '\x78',
  '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e', '\x7f', '\x9a',
  '\xbf', '\x9c', '\x00', '\x9d', '\x00', '\x00', '\x00', '\x00',
  '\x9e', '\x9f', '\xb3', '\xe1', '\xe2', '\xf7', '\xe7', '\xe4',
  '\xe5', '\xf6', '\xfa', '\xe9', '\xea', '\xeb', '\xec', '\xed',
  '\xee', '\xef', '\xf0', '\xf2', '\xf3', '\xf4', '\xf5', '\xe6',
  '\xe8', '\xe3', '\xfe', '\xfb', '\xfd', '\xff', '\xf9', '\xf8',
  '\xfc', '\xe0', '\xf1', '\xc1', '\xc2', '\xd7', '\xc7', '\xc4',
  '\xc5', '\xd6', '\xda', '\xc9', '\xca', '\xcb', '\xcc', '\xcd',
  '\xce', '\xcf', '\xd0', '\xd2', '\xd3', '\xd4', '\xd5', '\xc6',
  '\xc8', '\xc3', '\xde', '\xdb', '\xdd', '\xdf', '\xd9', '\xd8',
  '\xdc', '\xc0', '\xd1', '\x00', '\xa3', '\x95', '\x96', '\x97',
  '\x98', '\x99', '\x93', '\x9b', '\x80', '\x00', '\x81', '\x82',
  '\x00', '\x00', '\x00', '\x83', '\x00', '\x00', '\x00', '\x84',
  '\x00', '\x00', '\x00', '\x85', '\x00', '\x00', '\x00', '\x86',
  '\x87', '\x88', '\x89', '\x8a', '\xa0', '\xa1', '\xa2', '\xa4',
  '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xaa', '\xab', '\xac',
  '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb4', '\xb5',
  '\xb6', '\xb7', '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd',
  '\xbe', '\x8b', '\x00', '\x00', '\x00', '\x8c', '\x00', '\x00',
  '\x00', '\x8d', '\x00', '\x00', '\x00', '\x8e', '\x00', '\x00',
  '\x00', '\x8f', '\x90', '\x91', '\x92', '\x94',
};
