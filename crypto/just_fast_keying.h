// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_JUST_FAST_KEYING_H_
#define CRYPTO_JUST_FAST_KEYING_H_

#include "crypto/nonce.h"
#include "crypto/p256_key_exchange.h"

namespace crypto {

// Just Fast Keying payload
class JustFastKeying {
 public:
 	JustFastKeying();

  operator std::string () const;
  int Length() const;

 private:
  enum {
    // Nonce length, 256 bits
  	kNonceLength = 32,

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

  mutable std::string payload_;
};

}  // namespace crypto

#endif  // CRYPTO_JUST_FAST_KEYING_H_
