// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/just_fast_keying.h"

#include "base/logging.h"
#include "gtest/gtest.h"

namespace crypto {
namespace test {

// A simple test that checks the correct size of the payload
TEST(JustFastKeying, Size) {
  JustFastKeying jfk;

  std::string jfk_str(jfk);

  const int kLength(
    3 +   // Length of header (version, neg_type, phase)
    32 +  // Length of a SHA-256 in bytes
    91);  // Lenght of a X509 EC public key

  EXPECT_EQ(jfk_str.length(), kLength);
}

}  // namespace test
}  // namespace crypto
