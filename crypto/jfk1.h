// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_JFK1_H_
#define CRYPTO_JFK1_H_

#include <string>
#include "crypto/jfk.h"
#include "crypto/nonce.h"
#include "crypto/p256_key_exchange.h"

namespace crypto {

// Jfk1 is the reply message being sent to the other peer. It takes the first
// message received and checks that is well formed. This is done in Init. Once
// checked, it builds the reply message to send.

class Jfk1 : public Jfk {
 public:
  Jfk1();
  ~Jfk1() override;

  bool Init(base::StringPiece in) override;

  // Use a std::string conversion operator to get the binary representation of
  // this payload.
  operator std::string () const override;
  int Length() const override;

 private:
  enum {
    // Nonce length, 128 bits for the reply message
    kNonceLength = 16,

    // Phase 1, reply message to the first
    kPhase   = 1,
  };

  Nonce nonce_;

  // P256 curve public key in X.509 format
  P256KeyExchange pub_key_;

  // This is constant in this phase
  char phase_ { kPhase };

  // The payload is built only once, on a read. This shouldn't change as its
  // values are built on the constructor.
  mutable std::string payload_;
};

}  // namespace crypto

#endif  // CRYPTO_JFK1_H_
