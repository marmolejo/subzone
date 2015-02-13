// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_HANDSHAKE_H_
#define CRYPTO_HANDSHAKE_H_

#include <string>
#include "base/strings/string_piece.h"
#include "crypto/just_fast_keying.h"
#include "crypto/rijndael.h"

namespace crypto {

// Handshake creates the header information to send in each authentification.
// To build the key necessary for the communication we need the identities of
// the two peers. These identities are passed to the constructors in the |i0|
// and |i1| parameters.
class Handshake {
 public:
  Handshake(base::StringPiece i0, base::StringPiece i1);

  // BuildKey gets the simmetric Rijndael key that is derived from the
  // identities of the two peers.
  static std::string BuildKey(base::StringPiece i0, base::StringPiece i1);

  // Implicit conversion to std::string will yield the string of bytes of the
  // full packet, including the extra random padding.
  operator std::string ();

  // JFK accessor
  std::string GetJfkAsString() const;

 private:
  enum {
    kBlockSize = 32,  // 256-bit blocs, for the IV

    // These two values are taken from the reference daemon
    kMaxFreenetPacketSize = 1232,
    kMinPaddingLength = 100,
  };

  // This is the "content" of the message, the public ECDSA key
  JustFastKeying jfk1_;

  Nonce iv_;  // A random nonce
  int pre_padding_length_;
  int padding_length_;

  // Rijndael 256 CFB encryptor
  Rijndael rijndael_;

  // The bytes of the final message
  std::string message_;
};

}  // namespace crypto

#endif  // CRYPTO_HANDSHAKE_H_
