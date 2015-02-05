// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/handshake.h"
#include "crypto/random.h"
#include "base/rand_util.h"
#include "base/base64.h"
#include "crypto/sha2.h"
#include "base/strings/string_util.h"

namespace crypto {

Handshake::Handshake(base::StringPiece i0, base::StringPiece i1)
  : iv_(kBlockSize),
    pre_padding_length_(2 * kBlockSize + 2 + jfk1_.Length()),
    padding_length_(base::RandUint64() % std::min(
       static_cast<int>(kMinPaddingLength),
       kMaxFreenetPacketSize - pre_padding_length_)),
    rijndael_(BuildKey(i0, i1), static_cast<std::string>(iv_)) {
}

Handshake::~Handshake() {
}

// static
std::string Handshake::BuildKey(base::StringPiece i0, base::StringPiece i1) {
  // create simmetric key
  std::string i0_id;
  base::Base64Decode(i0, &i0_id);
  auto i0_hash(crypto::SHA256HashString(crypto::SHA256HashString(i0_id)));

  std::string i1_id;
  base::Base64Decode(i1, &i1_id);
  auto i1_hash(crypto::SHA256HashString(i1_id));

  std::string out_key;
  out_key.resize(kBlockSize);
  for (size_t i=0; i < i1_hash.length(); ++i)
    out_key[i] = i1_hash[i] ^ i0_hash[i];

  return out_key;
}

Handshake::operator std::string () {
  if (!message_.empty()) return message_;

  message_.append(iv_);
  rijndael_.Encrypt(crypto::SHA256HashString(static_cast<std::string>(jfk1_)),
                    &message_);

  // encrypt length
  int length = jfk1_.Length();
  char L[] = { static_cast<char>(length>>8),
               static_cast<char>(0xff & length) };
  rijndael_.Encrypt(base::StringPiece(L, sizeof(L)), &message_);

  // encrypt payload
  rijndael_.Encrypt(static_cast<std::string>(jfk1_), &message_);

  std::string rnd_bytes;
  crypto::RandBytes(WriteInto(&rnd_bytes, padding_length_+1), padding_length_);
  message_.append(rnd_bytes);

  return message_;
}

}  // namespace crypto
