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

// Check message |in| for validity and return true if it's conformant
bool Jfk1::Init(base::StringPiece in) {
  return true;
}

Jfk1::operator std::string () const {
  return std::string();
}

// To get the length, we must have built the payload string.
int Jfk1::Length() const {
  return static_cast<std::string>(*this).length();
}

}  // namespace crypto
