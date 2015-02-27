// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/jfk2.h"

#include <string>
#include "base/logging.h"
#include "crypto/hmac.h"
#include "crypto/sha2.h"

namespace crypto {

Jfk2::Jfk2()
  : nonce_(kNonceLength), transient_key_(kKeyLength) {
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

  // As the incoming message appears to be OK, just copy the 32 byte SHA256 of
  // peer's nonce for sending it later and copy peer's public key.
  in.substr(kHeaderSize, kNonceLengthInitiator).CopyToString(&peer_hash_nonce_);
  in.substr(kHeaderSize + kNonceLengthInitiator, kPublicKeySize)
    .CopyToString(&peer_public_key_);

  return pub_key_.Init();
}

Jfk2::operator std::string () const {
  if (!payload_.empty()) return payload_;

  const char header[] = { kVersion, kNegType, kPhase };

  // First the message header.
  payload_.append(header, 3);

  // Hash of peer's nonce, then our nonce
  payload_.append(peer_hash_nonce_);
  payload_.append(nonce_);

  // Our public key and the public key's signature in DER network format
  pub_key_.GetX509Public().AppendToString(&payload_);
  pub_key_.GetSignature().AppendToString(&payload_);

  // Pad signature with zeros till kSignatureSize (it must have a fixed size)
  payload_.append(kSignatureSize - pub_key_.GetSignature().length(), '\0');

  // 32 byte HMAC authenticator, based on a transient key
  HMAC hmac(crypto::HMAC::SHA256);
  hmac.Init(reinterpret_cast<const unsigned char*>(
    & (static_cast<std::string>(transient_key_)[0])), kKeyLength);

  // Data passed to HMAC is the concat of our public key, then peer's public key
  // Our nonce, their nonce hash and our public IP address, which for testing
  // purposes we will leave it as 127.0.0.1 for the moment.
  std::string hmac_data(pub_key_.GetX509Public().as_string());
  hmac_data.append(peer_public_key_);
  hmac_data.append(nonce_);
  hmac_data.append(peer_hash_nonce_);

  // FIXME: use hardcoded 127.0.0.1 as temporary address value
  hmac_data.append("\x7f\0\0\x1", 4);

  // Sign the authentication block and append it to the payload.
  uint8_t hmac_sign[kKeyLength];
  hmac.Sign(hmac_data, hmac_sign, kKeyLength);
  payload_.append(reinterpret_cast<char*>(hmac_sign), kKeyLength);

  return payload_;
}

// To get the length, we must have built the payload string.
int Jfk2::Length() const {
  return static_cast<std::string>(*this).length();
}

}  // namespace crypto
