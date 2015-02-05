// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_NONCE_H_
#define CRYPTO_NONCE_H_

#include <string>

namespace crypto {

// A n-bit nonce
class Nonce {
 public:
  explicit Nonce(std::size_t size);

  // Get the random string
  operator std::string() const;

 private:
  std::string nonce;
};

}  // namespace crypto

#endif  // CRYPTO_NONCE_H_
