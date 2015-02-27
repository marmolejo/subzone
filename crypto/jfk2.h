// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_JFK2_H_
#define CRYPTO_JFK2_H_

#include <string>
#include "base/gtest_prod_util.h"
#include "crypto/jfk.h"
#include "crypto/nonce.h"
#include "crypto/p256_key_exchange.h"

namespace crypto {

// Jfk2 is the reply message being sent to the other peer. It takes the first
// message received and checks that is well formed. This is done in Init. Once
// checked, it builds the reply message to send.

class Jfk2 : public Jfk {
 public:
  Jfk2();
  ~Jfk2() override;

  bool Init(base::StringPiece in) override;

  // Use a std::string conversion operator to get the binary representation of
  // this payload.
  operator std::string () const override;
  int Length() const override;

 private:
  FRIEND_TEST_ALL_PREFIXES(Jfk2, Init);

  enum {
    // Nonce length, 128 bits for the reply message
    kNonceLength = 16,

    // Phase 1, reply message to the first
    kPhase   = 1,

    // Transient key length
    kKeyLength = 32,

    // Signature length
    kSignatureSize = 72,
  };

  // Auxiliary function to verify the three bytes present in the header.
  bool VerifyHeader(base::StringPiece in);

  Nonce nonce_;
  Nonce transient_key_;

  // Get the peer nonce and peer public key from the incoming packet
  std::string peer_hash_nonce_;
  std::string peer_public_key_;

  // P256 curve public key in X.509 format
  P256KeyExchange pub_key_;

  // The payload is built only once, on a read. This shouldn't change as its
  // values are built on the constructor.
  mutable std::string payload_;
};

}  // namespace crypto

#endif  // CRYPTO_JFK2_H_
