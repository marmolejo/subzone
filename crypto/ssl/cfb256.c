/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

/*
 * This is just the crypto/modes/cfb.c from boringssl with 256-bit block size,
 * that is, in every place where it was read '16', substitute it by '32' :)
 */

#include "crypto/ssl/cfb256.h"

#include <assert.h>
#include <string.h>

void CRYPTO_cfb256_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                           const void *key, uint8_t ivec[32], int *num, int enc,
                           block256_f block) {
  unsigned int n;
  size_t l = 0;

  assert(in && out && key && ivec && num);
  assert((32 % sizeof(size_t)) == 0);

  n = *num;

  if (enc) {
    while (n && len) {
      *(out++) = ivec[n] ^= *(in++);
      --len;
      n = (n + 1) % 32;
    }
#if STRICT_ALIGNMENT
    if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      while (l < len) {
        if (n == 0) {
          (*block)(ivec, ivec, key);
        }
        out[l] = ivec[n] ^= in[l];
        ++l;
        n = (n + 1) % 32;
      }
      *num = n;
      return;
    }
#endif
    while (len >= 32) {
      (*block)(ivec, ivec, key);
      for (; n < 32; n += sizeof(size_t)) {
        *(size_t *)(out + n) = *(size_t *)(ivec + n) ^= *(size_t *)(in + n);
      }
      len -= 32;
      out += 32;
      in += 32;
      n = 0;
    }
    if (len) {
      (*block)(ivec, ivec, key);
      while (len--) {
        out[n] = ivec[n] ^= in[n];
        ++n;
      }
    }
    *num = n;
    return;
  } else {
    while (n && len) {
      uint8_t c;
      *(out++) = ivec[n] ^ (c = *(in++));
      ivec[n] = c;
      --len;
      n = (n + 1) % 32;
    }
    if (STRICT_ALIGNMENT && ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      while (l < len) {
        unsigned char c;
        if (n == 0) {
          (*block)(ivec, ivec, key);
        }
        out[l] = ivec[n] ^ (c = in[l]);
        ivec[n] = c;
        ++l;
        n = (n + 1) % 32;
      }
      *num = n;
      return;
    }
    while (len >= 32) {
      (*block)(ivec, ivec, key);
      for (; n < 32; n += sizeof(size_t)) {
        size_t t = *(size_t *)(in + n);
        *(size_t *)(out + n) = *(size_t *)(ivec + n) ^ t;
        *(size_t *)(ivec + n) = t;
      }
      len -= 32;
      out += 32;
      in += 32;
      n = 0;
    }
    if (len) {
      (*block)(ivec, ivec, key);
      while (len--) {
        uint8_t c;
        out[n] = ivec[n] ^ (c = in[n]);
        ivec[n] = c;
        ++n;
      }
    }
    *num = n;
    return;
  }
}
