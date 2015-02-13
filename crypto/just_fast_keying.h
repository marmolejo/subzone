// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_JUST_FAST_KEYING_H_
#define CRYPTO_JUST_FAST_KEYING_H_

#include <string>
#include "crypto/nonce.h"
#include "crypto/p256_key_exchange.h"

namespace crypto {

// JustFast Keying is the payload of the handshake message. It contains the
// public ECDSA key in X509 format, so the other peer can check it.

// Just Fast Keying payload
class JustFastKeying {
 public:
  JustFastKeying();

  // Use a std::string conversion operator to get the binary representation of
  // this payload.
  operator std::string () const;
  int Length() const;

 private:
  enum {
    // Nonce length, 256 bits
    kNonceLength = 32,

    // These values are harcoded as we only support for the moment these modes.
    // Handshake version, currently 1
    kVersion = 1,

    // Negotiation type 9 (the only one supported)
    kNegType = 9,

    // Phase 0, first message in the handshake
    kPhase   = 0,
  };

  Nonce nonce_;

  // P256 curve public key in X.509 format
  P256KeyExchange pub_key_;

  char version_ { kVersion };
  char neg_type_ { kNegType };
  char phase_ { kPhase };

  // The payload is built only once, on a read. This shouldn't change as its
  // values are built on the constructor.
  mutable std::string payload_;
};

}  // namespace crypto

#endif  // CRYPTO_JUST_FAST_KEYING_H_
