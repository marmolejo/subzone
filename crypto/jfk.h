// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_JFK_H_
#define CRYPTO_JFK_H_

#include <string>
#include "crypto/nonce.h"
#include "crypto/p256_key_exchange.h"

namespace crypto {

// Jfk abstract class represents a negotiation phase between two peers. This
// phase initializes by passing an incoming message in |in|. It can be empty if
// we are the initiators. In this case, there is only output message.
class Jfk {
 public:
  virtual ~Jfk() {}

  // Incoming message to check comes in |in|.
  virtual bool Init(base::StringPiece in) = 0;

  // Use a std::string conversion operator to get the binary representation of
  // this payload.
  virtual operator std::string () const = 0;
  virtual int Length() const = 0;

 protected:
  enum {
    // These values are harcoded as we only support for the moment these modes.
    // Handshake version, currently 1
    kVersion = 1,

    // Negotiation type 9 (the only one supported)
    kNegType = 9,
  };

  // These values, that are sent in any outgoing messages are constant, as we
  // don't support other versions or older negotiation types (pre-2013).
  const char version_ { kVersion };
  const char neg_type_ { kNegType };
};

}  // namespace crypto

#endif  // CRYPTO_JFK_H_
