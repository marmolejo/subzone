// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/jfk0.h"
#include "crypto/jfk1.h"

#include "base/logging.h"
#include "gtest/gtest.h"

namespace crypto {

const int kHeaderSize = 3;
const int kNonceLengthInitiator = 32;
const int kPublicKeySize = 91;

// A simple test that checks the correct size of the payload, just for the
// first message.
TEST(Jfk0, Size) {
  Jfk0 jfk;

  std::string jfk_str(jfk);

  const int kLength(
    kHeaderSize +            // Length of header (version, neg_type, phase)
    kNonceLengthInitiator +  // Length of a SHA-256 in bytes
    kPublicKeySize);         // Lenght of a X509 EC public key

  EXPECT_EQ(jfk_str.length(), kLength);
}


TEST(Jfk1, Init) {
  // This is an example phase1 payload taken from Freenet reference daemon. We
  // only check here that Init verifies the header, size and copies correct
  // bytes for peer's nonce and public key.
  const std::string kPayload = {
    1, 9, 0, -98, 36, 86, -99, -78, 54, 19, 42, -61, -53, 9, 17, 82,
    -81, 62, -27, 80, -53, 78, 72, 107, 110, 3, 21, -56, 16, -40, -7, 100,
    120, 115, -73, 48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1,
    6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4, 70, -101,
    -78, -17, 94, -41, 112, -104, -124, 29, -19, 41, -73, -57, 33, 20, -51, 102,
    117, -93, -48, 97, -7, -81, -31, 18, 19, 89, -30, -69, 60, -3, 27, -31,
    -4, 72, 17, 92, -56, 12, -34, 82, 126, -58, -29, -101, 123, 11, 106, 35,
    -9, -4, 62, 40, 46, 107, 21, -89, -48, 15, 105, 27, 86, -20,
  };

  Jfk1 jfk;
  EXPECT_TRUE(jfk.Init(kPayload));

  // Take the above substrings directly to match nonce and public key stored by
  // jfk1.
  EXPECT_EQ(jfk.peer_nonce_.compare(
    kPayload.substr(kHeaderSize, kNonceLengthInitiator)), 0);
  EXPECT_EQ(jfk.peer_public_key_.compare(
    kPayload.substr(kHeaderSize + kNonceLengthInitiator, kPublicKeySize)), 0);
}

}  // namespace crypto
