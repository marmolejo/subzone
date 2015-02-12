// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/rijndael.h"

namespace crypto {

Rijndael::Rijndael(base::StringPiece key, base::StringPiece iv)
    : num_(0) {
  DCHECK(key.length() == 16 || key.length() == 24 || key.length() == 32);

  // We only support 256-bit block sizes
  DCHECK_EQ(iv.length(), kBlockSize);

  iv.copy(reinterpret_cast<char *>(iv_), kBlockSize);

  // Expand the user-supplied key material into a session key
  RIJNDAEL256_set_encrypt_key(reinterpret_cast<const uint8_t *>(key.data()),
                              key.length()*8, &enc_key_);
}

void Rijndael::SetIV(base::StringPiece iv) {
  // We only support 256-bit block sizes
  DCHECK_EQ(iv.length(), kBlockSize);

  iv.copy(reinterpret_cast<char *>(iv_), kBlockSize);
}

bool Rijndael::Encrypt(const base::StringPiece in, std::string* out) {
  DCHECK(out);
  auto s(out->size());
  out->resize(s + in.size());

  std::string &out_ref = *out;
  auto out_buf(&out_ref[s]);
  RIJNDAEL256_cfb256_encrypt(reinterpret_cast<const uint8_t *>(in.data()),
                             reinterpret_cast<uint8_t *>(out_buf), in.size(),
                             &enc_key_, iv_, &num_, RIJNDAEL256_ENCRYPT);
}

bool Rijndael::Decrypt(const base::StringPiece in, std::string* out) {
  DCHECK(out);
  auto s(out->size());
  out->resize(s + in.size());

  std::string &out_ref = *out;
  auto out_buf(&out_ref[s]);
  RIJNDAEL256_cfb256_encrypt(reinterpret_cast<const uint8_t *>(in.data()),
                             reinterpret_cast<uint8_t *>(out_buf), in.size(),
                             &enc_key_, iv_, &num_, RIJNDAEL256_DECRYPT);
}

}  // namespace crypto
