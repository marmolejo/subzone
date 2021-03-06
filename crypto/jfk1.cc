// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/jfk1.h"

#include <string>
#include "crypto/sha2.h"

namespace crypto {

Jfk1::Jfk1()
  : nonce_(kNonceLength) {
}

Jfk1::~Jfk1() {
}

bool Jfk1::Init(base::StringPiece in) {
  // As the first message to be sent, ignore the parameter |in|.
  return pub_key_.Init();
}

Jfk1::operator std::string () const {
  if (!payload_.empty()) return payload_;

  const char header[] = { kVersion, kNegType, kPhase };

  // First the message header.
  payload_.append(header, 3);

  // Then send the SHA-256 hash of the message
  payload_.append(crypto::SHA256HashString(static_cast<std::string>(nonce_)));

  // Finally the X509 public key
  pub_key_.GetX509Public().AppendToString(&payload_);

  return payload_;
}

// To get the length, we must have built the payload string.
int Jfk1::Length() const {
  return static_cast<std::string>(*this).length();
}

}  // namespace crypto
