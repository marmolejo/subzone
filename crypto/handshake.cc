// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/handshake.h"

#include "base/base64.h"
#include "base/rand_util.h"
#include "base/strings/string_util.h"
#include "crypto/jfk0.h"
#include "crypto/jfk1.h"
#include "crypto/random.h"
#include "crypto/sha2.h"

namespace crypto {

Handshake::Handshake(base::StringPiece i0, base::StringPiece i1,
                     bool initiator)
    : jfk_(initiator ?
           static_cast<std::unique_ptr<Jfk>>(std::make_unique<Jfk0>())
         : static_cast<std::unique_ptr<Jfk>>(std::make_unique<Jfk1>())),
      phase_(initiator ? 0 : 1),
      iv_(kBlockSize),
      rijndael_(BuildKey(i0, i1), static_cast<std::string>(iv_)) {
  DCHECK_EQ(i0.length(), 43);  // base64 encoding of an Identity
  DCHECK_EQ(i0.length(), 43);
}

// This method builds the symmetric outgoing Rijndael key, the incoming key is
// different as it's created by XORing the double hash of the peer's identity
// together with the single hash of our identity.

// static
std::string Handshake::BuildKey(base::StringPiece i0, base::StringPiece i1) {
  // create simmetric key
  // Our identity gets double hashed, while the peer's is single hashed
  std::string i0_id;
  base::Base64Decode(i0, &i0_id);
  auto i0_hash(crypto::SHA256HashString(crypto::SHA256HashString(i0_id)));

  std::string i1_id;
  base::Base64Decode(i1, &i1_id);
  auto i1_hash(crypto::SHA256HashString(i1_id));

  // We XOR together the 2 identities.
  std::string out_key;
  out_key.resize(kBlockSize);
  for (size_t i=0; i < i1_hash.length(); ++i)
    out_key[i] = i1_hash[i] ^ i0_hash[i];

  return out_key;
}

bool Handshake::NextPhase(base::StringPiece in, std::string *out) {
  DCHECK(out);

  // Initialize properly the current phase we are with the incoming message.
  // If incoming message is malformed, return false.
  if (!jfk_->Init(in)) {
    DVLOG(1) << "Wrong format for incoming message in phase " << phase_;
    return false;
  }

  // Once the payload is done for the next message, just build the auth packet
  // by encrypting the payload and adding the hash.
  BuildAuthPacket(out);

  return true;
}

void Handshake::BuildAuthPacket(std::string *out) {
  DCHECK(out);

  // First the initial vector.
  out->append(iv_);

  // Then we encrypt the SHA-256 hash of the payload
  rijndael_.Encrypt(crypto::SHA256HashString(static_cast<std::string>(*jfk_)),
                    out);

  // Encrypt length
  int length = jfk_->Length();
  char L[] = { static_cast<char>(length>>8),
               static_cast<char>(0xff & length) };
  rijndael_.Encrypt(base::StringPiece(L, sizeof(L)), out);

  // Encrypt payload
  rijndael_.Encrypt(static_cast<std::string>(*jfk_), out);

  // Add some extra random bytes.
  auto pre_padding_length_(2 * kBlockSize + 2 + length);

  // The payload cannot be larger than the MaxFreenetPacketSize, otherwise it
  // won't fit.
  DCHECK_GE(kMaxFreenetPacketSize, pre_padding_length_);

  // Will be padding at max 100 bytes extra, it can be less if the package is
  // big enough.
  auto padding_length_(base::RandUint64() % std::min(
    static_cast<int>(kMinPaddingLength),
    kMaxFreenetPacketSize - pre_padding_length_));

  if (padding_length_) {
    std::string rnd_bytes;
    crypto::RandBytes(WriteInto(&rnd_bytes, padding_length_+1),
                      padding_length_);
    out->append(rnd_bytes);
  }
}

}  // namespace crypto
