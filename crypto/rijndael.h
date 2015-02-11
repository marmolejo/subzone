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

class Rijndael {
 public:
  Rijndael(base::StringPiece key, base::StringPiece iv);

  void SetIV(base::StringPiece iv);

  bool Encrypt(const base::StringPiece in, std::string &out);
  bool Decrypt(const base::StringPiece in, std::string &out);

 private:
  enum { kBlockSize = 32, };

  // Data structure that contains the key itself
  RIJNDAEL256_KEY enc_key_;

  uint8_t iv_[kBlockSize];

  int num_;
};

}  // namespace crypto

#endif  // CRYPTO_RIJNDAEL_H_
