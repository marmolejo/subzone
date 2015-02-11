/*
 * Copyright 2015 The Subzone Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * This is a recreation of the crypto/aes/mode_wrappers.c with only
 * Rijndael-256 block cipher and CFB256 mode.
 */

#include "crypto/ssl/cfb256.h"
#include "crypto/ssl/rijndael.h"

void RIJNDAEL256_cfb256_encrypt(const uint8_t *in, uint8_t *out,
                                size_t length, const RIJNDAEL256_KEY *key,
                                uint8_t *ivec, int *num, int enc) {
  CRYPTO_cfb256_encrypt(in, out, length, key, ivec, num, enc,
                        (block256_f)RIJNDAEL256_encrypt);
}
