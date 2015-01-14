// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_HANDSHAKE_H_
#define CRYPTO_HANDSHAKE_H_

#include "base/strings/string_piece.h"
#include "crypto/just_fast_keying.h"
#include "contrib/crypto/rijndael.h"

namespace crypto {

class Handshake {
 public:
 	Handshake(base::StringPiece i0, base::StringPiece i1);

  operator std::string ();

 private:
  enum {
    kBlockSize = 32,
    kMaxFreenetPacketSize = 1232,
    kMinPaddingLength = 100,
  };

  static std::string BuildKey(base::StringPiece i0, base::StringPiece i1);

 	JustFastKeying jfk1_;
 	Nonce iv_;
  int pre_padding_length_;
  int padding_length_;
  Rijndael rijndael_;

  std::string message_;
};

}  // namespace crypto

#endif  // CRYPTO_HANDSHAKE_H_
