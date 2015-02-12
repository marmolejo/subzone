/*
 * Copyright 2015 The Subzone Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CRYPTO_SSL_RIJNDAEL_H_
#define CRYPTO_SSL_RIJNDAEL_H_

#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Raw AES functions. */


#define RIJNDAEL256_ENCRYPT 1
#define RIJNDAEL256_DECRYPT 0

/* RIJNDAEL256_MAXNR is the maximum number of RIJNDAEL256 rounds. */
#define RIJNDAEL256_MAXNR 14

#define RIJNDAEL256_BLOCK_SIZE 32

/* aes_key_st should be an opaque type, but EVP requires that the size be
 * known. */
struct rijndael256_key_st {
  uint32_t rd_key[8 * (RIJNDAEL256_MAXNR + 1)];
  unsigned rounds;
};
typedef struct rijndael256_key_st RIJNDAEL256_KEY;

/* RIJNDAEL256_set_encrypt_key configures |aeskey| to encrypt with the
 * |bits|-bit key, |key|.
 *
 * WARNING: unlike other OpenSSL functions, this returns zero on success and a
 * negative number on error. */
int RIJNDAEL256_set_encrypt_key(const uint8_t *key, unsigned bits,
                                RIJNDAEL256_KEY *aeskey);

/* RIJNDAEL256_encrypt encrypts a single block from |in| to |out| with |key|.
 * The |in| and |out| pointers may overlap. */
void RIJNDAEL256_encrypt(const uint8_t *in, uint8_t *out,
                         const RIJNDAEL256_KEY *key);

/* RIJNDAEL256_cfb256_encrypt encrypts (or decrypts, if |enc| ==
 * |RIJNDAEL256_DECRYPT|) |len| bytes from |in| to |out|. The |num| parameter
 * must be set to zero on the first call. */
void RIJNDAEL256_cfb256_encrypt(const uint8_t *in, uint8_t *out,
                                size_t len, const RIJNDAEL256_KEY *key,
                                uint8_t *ivec, int *num, int enc);

#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* CRYPTO_SSL_RIJNDAEL_H_ */
