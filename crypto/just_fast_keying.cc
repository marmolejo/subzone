// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/just_fast_keying.h"
#include "crypto/sha2.h"

namespace crypto {

JustFastKeying::JustFastKeying()
  : nonce_ (kNonceLength) {
}

const std::string& JustFastKeying::ToString() const {
	if(!payload_.empty()) return payload_;

  const char header [] = { version_, neg_type_, phase_ };
	payload_.append(header, 3);
	payload_.append(crypto::SHA256HashString(nonce_.ToString()));
	pub_key_.GetX509Public().AppendToString(&payload_);

	return payload_;
}

}  // namespace crypto
