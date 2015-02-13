// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_RIJNDAEL_H_
#define CRYPTO_RIJNDAEL_H_

#include <string>
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "crypto/ssl/rijndael.h"

namespace crypto {

// This class is the C++ wrapper for the ssl/* Rijndael 256-bit block size C
// implementation based on AES, with 128 bit block size. This class uses the
// CFB mode to encrypt an arbitrary number of bytes. The register size matches
// the block size, which is 32 bytes.
class Rijndael {
 public:
  // Build the session key in the constructor using |key|, and set the Initial
  // Vector |iv| for the CFB chain. Both arguments are strings of 32 bytes
  // (256-bits). Usually key size and block size are unrelated, but in this
  // case they match.
  Rijndael(base::StringPiece key, base::StringPiece iv);

  // Some syntactic sugar to be able to change the IV once initialized.
  void SetIV(base::StringPiece iv);

  // Encrypt & Decrypt an arbitrary number of bytes placed in |in|, to output
  // parameter |out|. |out| must have the same number of bytes as |in|.
  bool Encrypt(const base::StringPiece in, std::string* out);
  bool Decrypt(const base::StringPiece in, std::string* out);

 private:
  // Block size is fixed as 256-bit.
  enum { kBlockSize = 32, };

  // Data structure that contains the key itself
  RIJNDAEL256_KEY enc_key_;

  uint8_t iv_[kBlockSize];

  // This is necessary for successive calls to the ssl/* CFB chain. It is the
  // position in the feedback register.
  int num_;
};

}  // namespace crypto

#endif  // CRYPTO_RIJNDAEL_H_
