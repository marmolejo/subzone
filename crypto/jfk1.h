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

// Jfk1 is the first message being sent to the other peer. It has the public
// ECDSA key in X509 format, so the other peer can check it.

// Just Fast Keying payload
class Jfk1 : public Jfk {
 public:
  Jfk1();
  ~Jfk1() override;

  // Here |in| is ignored, as is the first message, it has no incoming.
  bool Init(base::StringPiece in) override;

  // Use a std::string conversion operator to get the binary representation of
  // this payload.
  operator std::string () const override;
  int Length() const override;

 private:
  enum {
    // Nonce length, 256 bits for the first message
    kNonceLength = 32,

    // Phase 0, first message in the handshake
    kPhase   = 0,
  };

  Nonce nonce_;

  // P256 curve public key in X.509 format
  P256KeyExchange pub_key_;

  // The payload is built only once, on a read. This shouldn't change as its
  // values are built on the constructor.
  mutable std::string payload_;
};

}  // namespace crypto

#endif  // CRYPTO_JFK1_H_
