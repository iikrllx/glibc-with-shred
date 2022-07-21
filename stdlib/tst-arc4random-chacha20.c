/* Basic tests for chacha20 cypher used in arc4random.
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

#include <arc4random.h>
#include <support/check.h>
#include <sys/cdefs.h>

/* The test does not define CHACHA20_XOR_FINAL to mimic what arc4random
   actual does.  */
#include <chacha20.c>

static int
do_test (void)
{
  const uint8_t key[CHACHA20_KEY_SIZE] =
    {
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    };
  const uint8_t iv[CHACHA20_IV_SIZE] =
    {
      0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    };
  const uint8_t expected1[CHACHA20_BUFSIZE] =
    {
      0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a,
      0xe5, 0x53, 0x86, 0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d,
      0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7, 0xda,
      0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f,
      0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1,
      0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86, 0x9f, 0x07,
      0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a, 0x98, 0xba, 0x97, 0x7c, 0x73,
      0x2d, 0x08, 0x0d, 0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
      0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed, 0x29, 0xb7, 0x21,
      0x76, 0x9c, 0xe6, 0x4e, 0x43, 0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8,
      0x39, 0xd5, 0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45, 0xac,
      0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f, 0x2d, 0x09, 0xa0, 0xe6,
      0x63, 0x26, 0x6c, 0xe1, 0xae, 0x7e, 0xd1, 0x08, 0x19, 0x68, 0xa0,
      0x75, 0x8e, 0x71, 0x8e, 0x99, 0x7b, 0xd3, 0x62, 0xc6, 0xb0, 0xc3,
      0x46, 0x34, 0xa9, 0xa0, 0xb3, 0x5d, 0x01, 0x27, 0x37, 0x68, 0x1f,
      0x7b, 0x5d, 0x0f, 0x28, 0x1e, 0x3a, 0xfd, 0xe4, 0x58, 0xbc, 0x1e,
      0x73, 0xd2, 0xd3, 0x13, 0xc9, 0xcf, 0x94, 0xc0, 0x5f, 0xf3, 0x71,
      0x62, 0x40, 0xa2, 0x48, 0xf2, 0x13, 0x20, 0xa0, 0x58, 0xd7, 0xb3,
      0x56, 0x6b, 0xd5, 0x20, 0xda, 0xaa, 0x3e, 0xd2, 0xbf, 0x0a, 0xc5,
      0xb8, 0xb1, 0x20, 0xfb, 0x85, 0x27, 0x73, 0xc3, 0x63, 0x97, 0x34,
      0xb4, 0x5c, 0x91, 0xa4, 0x2d, 0xd4, 0xcb, 0x83, 0xf8, 0x84, 0x0d,
      0x2e, 0xed, 0xb1, 0x58, 0x13, 0x10, 0x62, 0xac, 0x3f, 0x1f, 0x2c,
      0xf8, 0xff, 0x6d, 0xcd, 0x18, 0x56, 0xe8, 0x6a, 0x1e, 0x6c, 0x31,
      0x67, 0x16, 0x7e, 0xe5, 0xa6, 0x88, 0x74, 0x2b, 0x47, 0xc5, 0xad,
      0xfb, 0x59, 0xd4, 0xdf, 0x76, 0xfd, 0x1d, 0xb1, 0xe5, 0x1e, 0xe0,
      0x3b, 0x1c, 0xa9, 0xf8, 0x2a, 0xca, 0x17, 0x3e, 0xdb, 0x8b, 0x72,
      0x93, 0x47, 0x4e, 0xbe, 0x98, 0x0f, 0x90, 0x4d, 0x10, 0xc9, 0x16,
      0x44, 0x2b, 0x47, 0x83, 0xa0, 0xe9, 0x84, 0x86, 0x0c, 0xb6, 0xc9,
      0x57, 0xb3, 0x9c, 0x38, 0xed, 0x8f, 0x51, 0xcf, 0xfa, 0xa6, 0x8a,
      0x4d, 0xe0, 0x10, 0x25, 0xa3, 0x9c, 0x50, 0x45, 0x46, 0xb9, 0xdc,
      0x14, 0x06, 0xa7, 0xeb, 0x28, 0x15, 0x1e, 0x51, 0x50, 0xd7, 0xb2,
      0x04, 0xba, 0xa7, 0x19, 0xd4, 0xf0, 0x91, 0x02, 0x12, 0x17, 0xdb,
      0x5c, 0xf1, 0xb5, 0xc8, 0x4c, 0x4f, 0xa7, 0x1a, 0x87, 0x96, 0x10,
      0xa1, 0xa6, 0x95, 0xac, 0x52, 0x7c, 0x5b, 0x56, 0x77, 0x4a, 0x6b,
      0x8a, 0x21, 0xaa, 0xe8, 0x86, 0x85, 0x86, 0x8e, 0x09, 0x4c, 0xf2,
      0x9e, 0xf4, 0x09, 0x0a, 0xf7, 0xa9, 0x0c, 0xc0, 0x7e, 0x88, 0x17,
      0xaa, 0x52, 0x87, 0x63, 0x79, 0x7d, 0x3c, 0x33, 0x2b, 0x67, 0xca,
      0x4b, 0xc1, 0x10, 0x64, 0x2c, 0x21, 0x51, 0xec, 0x47, 0xee, 0x84,
      0xcb, 0x8c, 0x42, 0xd8, 0x5f, 0x10, 0xe2, 0xa8, 0xcb, 0x18, 0xc3,
      0xb7, 0x33, 0x5f, 0x26, 0xe8, 0xc3, 0x9a, 0x12, 0xb1, 0xbc, 0xc1,
      0x70, 0x71, 0x77, 0xb7, 0x61, 0x38, 0x73, 0x2e, 0xed, 0xaa, 0xb7,
      0x4d, 0xa1, 0x41, 0x0f, 0xc0, 0x55, 0xea, 0x06, 0x8c, 0x99, 0xe9,
      0x26, 0x0a, 0xcb, 0xe3, 0x37, 0xcf, 0x5d, 0x3e, 0x00, 0xe5, 0xb3,
      0x23, 0x0f, 0xfe, 0xdb, 0x0b, 0x99, 0x07, 0x87, 0xd0, 0xc7, 0x0e,
      0x0b, 0xfe, 0x41, 0x98, 0xea, 0x67, 0x58, 0xdd, 0x5a, 0x61, 0xfb,
      0x5f, 0xec, 0x2d, 0xf9, 0x81, 0xf3, 0x1b, 0xef, 0xe1, 0x53, 0xf8,
      0x1d, 0x17, 0x16, 0x17, 0x84, 0xdb
    };

  const uint8_t expected2[CHACHA20_BUFSIZE] =
    {
      0x1c, 0x88, 0x22, 0xd5, 0x3c, 0xd1, 0xee, 0x7d, 0xb5, 0x32, 0x36,
      0x48, 0x28, 0xbd, 0xf4, 0x04, 0xb0, 0x40, 0xa8, 0xdc, 0xc5, 0x22,
      0xf3, 0xd3, 0xd9, 0x9a, 0xec, 0x4b, 0x80, 0x57, 0xed, 0xb8, 0x50,
      0x09, 0x31, 0xa2, 0xc4, 0x2d, 0x2f, 0x0c, 0x57, 0x08, 0x47, 0x10,
      0x0b, 0x57, 0x54, 0xda, 0xfc, 0x5f, 0xbd, 0xb8, 0x94, 0xbb, 0xef,
      0x1a, 0x2d, 0xe1, 0xa0, 0x7f, 0x8b, 0xa0, 0xc4, 0xb9, 0x19, 0x30,
      0x10, 0x66, 0xed, 0xbc, 0x05, 0x6b, 0x7b, 0x48, 0x1e, 0x7a, 0x0c,
      0x46, 0x29, 0x7b, 0xbb, 0x58, 0x9d, 0x9d, 0xa5, 0xb6, 0x75, 0xa6,
      0x72, 0x3e, 0x15, 0x2e, 0x5e, 0x63, 0xa4, 0xce, 0x03, 0x4e, 0x9e,
      0x83, 0xe5, 0x8a, 0x01, 0x3a, 0xf0, 0xe7, 0x35, 0x2f, 0xb7, 0x90,
      0x85, 0x14, 0xe3, 0xb3, 0xd1, 0x04, 0x0d, 0x0b, 0xb9, 0x63, 0xb3,
      0x95, 0x4b, 0x63, 0x6b, 0x5f, 0xd4, 0xbf, 0x6d, 0x0a, 0xad, 0xba,
      0xf8, 0x15, 0x7d, 0x06, 0x2a, 0xcb, 0x24, 0x18, 0xc1, 0x76, 0xa4,
      0x75, 0x51, 0x1b, 0x35, 0xc3, 0xf6, 0x21, 0x8a, 0x56, 0x68, 0xea,
      0x5b, 0xc6, 0xf5, 0x4b, 0x87, 0x82, 0xf8, 0xb3, 0x40, 0xf0, 0x0a,
      0xc1, 0xbe, 0xba, 0x5e, 0x62, 0xcd, 0x63, 0x2a, 0x7c, 0xe7, 0x80,
      0x9c, 0x72, 0x56, 0x08, 0xac, 0xa5, 0xef, 0xbf, 0x7c, 0x41, 0xf2,
      0x37, 0x64, 0x3f, 0x06, 0xc0, 0x99, 0x72, 0x07, 0x17, 0x1d, 0xe8,
      0x67, 0xf9, 0xd6, 0x97, 0xbf, 0x5e, 0xa6, 0x01, 0x1a, 0xbc, 0xce,
      0x6c, 0x8c, 0xdb, 0x21, 0x13, 0x94, 0xd2, 0xc0, 0x2d, 0xd0, 0xfb,
      0x60, 0xdb, 0x5a, 0x2c, 0x17, 0xac, 0x3d, 0xc8, 0x58, 0x78, 0xa9,
      0x0b, 0xed, 0x38, 0x09, 0xdb, 0xb9, 0x6e, 0xaa, 0x54, 0x26, 0xfc,
      0x8e, 0xae, 0x0d, 0x2d, 0x65, 0xc4, 0x2a, 0x47, 0x9f, 0x08, 0x86,
      0x48, 0xbe, 0x2d, 0xc8, 0x01, 0xd8, 0x2a, 0x36, 0x6f, 0xdd, 0xc0,
      0xef, 0x23, 0x42, 0x63, 0xc0, 0xb6, 0x41, 0x7d, 0x5f, 0x9d, 0xa4,
      0x18, 0x17, 0xb8, 0x8d, 0x68, 0xe5, 0xe6, 0x71, 0x95, 0xc5, 0xc1,
      0xee, 0x30, 0x95, 0xe8, 0x21, 0xf2, 0x25, 0x24, 0xb2, 0x0b, 0xe4,
      0x1c, 0xeb, 0x59, 0x04, 0x12, 0xe4, 0x1d, 0xc6, 0x48, 0x84, 0x3f,
      0xa9, 0xbf, 0xec, 0x7a, 0x3d, 0xcf, 0x61, 0xab, 0x05, 0x41, 0x57,
      0x33, 0x16, 0xd3, 0xfa, 0x81, 0x51, 0x62, 0x93, 0x03, 0xfe, 0x97,
      0x41, 0x56, 0x2e, 0xd0, 0x65, 0xdb, 0x4e, 0xbc, 0x00, 0x50, 0xef,
      0x55, 0x83, 0x64, 0xae, 0x81, 0x12, 0x4a, 0x28, 0xf5, 0xc0, 0x13,
      0x13, 0x23, 0x2f, 0xbc, 0x49, 0x6d, 0xfd, 0x8a, 0x25, 0x68, 0x65,
      0x7b, 0x68, 0x6d, 0x72, 0x14, 0x38, 0x2a, 0x1a, 0x00, 0x90, 0x30,
      0x17, 0xdd, 0xa9, 0x69, 0x87, 0x84, 0x42, 0xba, 0x5a, 0xff, 0xf6,
      0x61, 0x3f, 0x55, 0x3c, 0xbb, 0x23, 0x3c, 0xe4, 0x6d, 0x9a, 0xee,
      0x93, 0xa7, 0x87, 0x6c, 0xf5, 0xe9, 0xe8, 0x29, 0x12, 0xb1, 0x8c,
      0xad, 0xf0, 0xb3, 0x43, 0x27, 0xb2, 0xe0, 0x42, 0x7e, 0xcf, 0x66,
      0xb7, 0xce, 0xb7, 0xc0, 0x91, 0x8d, 0xc4, 0x7b, 0xdf, 0xf1, 0x2a,
      0x06, 0x2a, 0xdf, 0x07, 0x13, 0x30, 0x09, 0xce, 0x7a, 0x5e, 0x5c,
      0x91, 0x7e, 0x01, 0x68, 0x30, 0x61, 0x09, 0xb7, 0xcb, 0x49, 0x65,
      0x3a, 0x6d, 0x2c, 0xae, 0xf0, 0x05, 0xde, 0x78, 0x3a, 0x9a, 0x9b,
      0xfe, 0x05, 0x38, 0x1e, 0xd1, 0x34, 0x8d, 0x94, 0xec, 0x65, 0x88,
      0x6f, 0x9c, 0x0b, 0x61, 0x9c, 0x52, 0xc5, 0x53, 0x38, 0x00, 0xb1,
      0x6c, 0x83, 0x61, 0x72, 0xb9, 0x51, 0x82, 0xdb, 0xc5, 0xee, 0xc0,
      0x42, 0xb8, 0x9e, 0x22, 0xf1, 0x1a, 0x08, 0x5b, 0x73, 0x9a, 0x36,
      0x11, 0xcd, 0x8d, 0x83, 0x60, 0x18
    };

  /* Check with the expected internal arc4random keystream buffer.  Some
     architecture optimizations expects a buffer with a minimum size which
     is a multiple of then ChaCha20 blocksize, so they might not be prepared
     to handle smaller buffers.  */

  uint8_t output[CHACHA20_BUFSIZE];

  uint32_t state[CHACHA20_STATE_LEN];
  chacha20_init (state, key, iv);

  /* Check with the initial state.  */
  uint8_t input[CHACHA20_BUFSIZE] = { 0 };

  chacha20_crypt (state, output, input, CHACHA20_BUFSIZE);
  TEST_COMPARE_BLOB (output, sizeof output, expected1, CHACHA20_BUFSIZE);

  /* And on the next round.  */
  chacha20_crypt (state, output, input, CHACHA20_BUFSIZE);
  TEST_COMPARE_BLOB (output, sizeof output, expected2, CHACHA20_BUFSIZE);

  return 0;
}

#include <support/test-driver.c>
