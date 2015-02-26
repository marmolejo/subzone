// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/jfk2.h"

#include <string>
#include "base/logging.h"
#include "crypto/sha2.h"

namespace crypto {

Jfk2::Jfk2()
  : nonce_(kNonceLength) {
}

Jfk2::~Jfk2() {
}

// Here give specific error messages for each byte that is incorrect. If header
// bytes don't match current packet, return false, otherwise for a correct
// header return true.
bool Jfk2::VerifyHeader(base::StringPiece in) {
  DCHECK_GE(in.length(), 3);

  if (in[0] != kVersion) {
    DVLOG(1) << "Only version 1 supported.";
    return false;
  }

  if (in[1] != kNegType) {
    DVLOG(1) << "Only NegType of 9 is supported.";
    return false;
  }

  if (in[2] != kPhase - 1) {
    DVLOG(1) << "This message should be in phase " << kPhase - 1;
    return false;
  }

  return true;
}

// Check message |in| for validity and return true if it's conformant
bool Jfk2::Init(base::StringPiece in) {
  const int kHeaderSize = 3;
  const int kNonceLengthInitiator = 32;
  const int kPublicKeySize = 91;

  // First, check message size. As padding is already removed in the Handshake,
  // length should be an exact number.
  if (in.length() != kHeaderSize + kNonceLengthInitiator + kPublicKeySize) {
    DVLOG(1) << "Packet has wrong length.";
    return false;
  }

  // Check that the 3 bytes in the header match the current phase and neg type.
  if (!VerifyHeader(in)) {
    DVLOG(1) << "Error parsing packet header.";
    return false;
  }

  // As the incoming message appears to be OK, just copy the 32 byte nonce for
  // sending it later and copy peer's public key.
  in.substr(kHeaderSize, kNonceLengthInitiator).CopyToString(&peer_nonce_);
  in.substr(kHeaderSize + kNonceLengthInitiator, kPublicKeySize)
    .CopyToString(&peer_public_key_);

  return pub_key_.Init();
}

Jfk2::operator std::string () const {
  return std::string();
}

// To get the length, we must have built the payload string.
int Jfk2::Length() const {
  return static_cast<std::string>(*this).length();
}

}  // namespace crypto
