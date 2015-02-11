// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/nonce.h"
#include "crypto/random.h"
#include "base/strings/string_util.h"

namespace crypto {

Nonce::Nonce(size_t size) {
  if (size)  // If size is 0, WriteInto will fail.
    crypto::RandBytes(WriteInto(&nonce_, size + 1), size);
}

Nonce::operator std::string() const {
  return nonce_;
}

}  // namespace crypto
