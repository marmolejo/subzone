/*
 * Copyright 2015 The Subzone Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef OPENSSL_HEADER_CFB256_H
#define OPENSSL_HEADER_CFB256_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* cfb256.h contains functions that implement CFB mode in 256-bit block size
 * This is a recreation of include/openssl/modes.h just with the new mode */

/* We don't use ASM for the moment */
#define STRICT_ALIGNMENT 1


/* block256_f is the type of a 256-bit, block cipher. */
typedef void (*block256_f)(const uint8_t in[32], uint8_t out[32],
                           const void *key);


/* CRYPTO_cfb256_encrypt encrypts (or decrypts, if |enc| is zero) |len| bytes
 * from |in| to |out| using |block| in CFB mode. There's no requirement that
 * |len| be a multiple of any value and any partial blocks are stored in |ivec|
 * and |*num|, the latter must be zero before the initial call. */
void CRYPTO_cfb256_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const void *key, uint8_t ivec[32], int *num, int enc,
                           block256_f block);

#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CFB256_H */
