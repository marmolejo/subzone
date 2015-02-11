// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/handshake.h"

#include <memory>
#include "gtest/gtest.h"
#include "base/logging.h"
#include "crypto/sha2.h"

namespace crypto {
namespace test {

const std::string kId1 = "gAXIdY1ZIY5imCwcISPDmkUCfEf0iT463+k2PkAh8Cw";
const std::string kId2 = "tMh1zG3Vy+c+dfeGqPRn+Df9Ich0K89U6SiAci2hgPk";
const std::string kId3 = "HupvjSHPGi8aB1bXeyU0X79V1jLp/nIoc4ERtREO6SE";

// Buildkey test, these values are taken from the Freenet reference daemon peer
// node tests. Each identity (kId*) produces two keys: the outgoing and the
// incoming key for communicating with the other peer. This test checks that
// keys are created correctly and match these ones created by the Freenet
// reference daemon.
TEST(Handshake, BuildKey) {
  const std::string kKey12 = {
    107, 28, 18, -6, 115, 83, -28, -117,
    -46, -24, -109, -51, -28, -31, -30, -39,
    3, 40, -56, -82, 0, -76, 113, 115,
    -125, -64, 52, -52, 80, -122, 124, -73,
  };

  const std::string kKey21 = {
    -24, -76, 69, 89, 25, 6, 101, -29,
    -46, -75, 127, 107, -57, 120, 84, 72,
    66, 33, 25, 72, 84, 15, 98, -124,
    120, 32, -50, -40, 73, 42, 62, -60,
  };

  const std::string kKey13 = {
    -87, -123, -57, -47, -29, 32, 27, -28,
    -113, 36, -28, -3, -97, 23, -100, -7,
    -33, 37, 35, 15, 122, 68, -18, 73,
    -42, 61, -37, -43, -13, -72, -26, -35,
  };

  const std::string kKey31 = {
    39, -29, -127, 120, 14, 70, 1, 94,
    -41, 81, -113, -37, 49, 23, -43, 69,
    -112, 20, -30, -67, 62, 30, -59, -115,
    -105, -46, 76, -21, 108, 2, 100, -39,
  };

  const std::string kKey23 = {
    91, 124, 120, -95, -103, -22, 3, 98,
    45, -57, 9, 46, -88, 93, 57, 113,
    55, 110, -72, -73, -65, -21, -4, -25,
    27, 17, 75, 37, -111, -15, -71, -81,
  };

  const std::string kKey32 = {
    86, -78, 105, -85, 30, -39, -104, -80,
    117, -17, -114, -82, 37, -60, -58, 92,
    57, 86, -88, -29, -81, 10, -60, -44,
    -95, 30, 38, 15, 23, -25, 121, -40,
  };

  EXPECT_EQ(Handshake::BuildKey(kId1, kId2).compare(kKey12), 0);
  EXPECT_EQ(Handshake::BuildKey(kId2, kId1).compare(kKey21), 0);
  EXPECT_EQ(Handshake::BuildKey(kId1, kId3).compare(kKey13), 0);
  EXPECT_EQ(Handshake::BuildKey(kId3, kId1).compare(kKey31), 0);
  EXPECT_EQ(Handshake::BuildKey(kId2, kId3).compare(kKey23), 0);
  EXPECT_EQ(Handshake::BuildKey(kId3, kId2).compare(kKey32), 0);
}

// Decrypt a message and obtain the payload from a generated handshake,
// decrypted payload and hash must match with handshake payload and
// computed hash
TEST(Handshake, EncryptDecrypt) {
  for (int i = 0; i < 5; i++) {
    Handshake hs(kId1, kId2);
    std::string jfkstr(*hs.getJFK());
    std::string message(hs);

    // First get the IV
    const auto kBlockSize(32);
    std::string iv(message, 0, kBlockSize);
    std::string message_enc(message, kBlockSize);

    // Decrypt message
    Rijndael rijndael(Handshake::BuildKey(kId1, kId2), iv);

    std::string message_dec;
    rijndael.Decrypt(message_enc, message_dec);

    // Get hash
    int pos(0);
    std::string hash(message_dec, pos, 32);

    // Get length
    pos+=32;
    std::string length_str(message_dec, pos, 2);

    // Process length
    int length = { static_cast<uint8_t>(length_str[0])*256 +
                   static_cast<uint8_t>(length_str[1]) };

    // Get payload
    pos+=2;
    std::string payload(message_dec, pos, length);
    EXPECT_EQ(jfkstr.compare(payload), 0);

    // Hash must match with message hash
    EXPECT_EQ(hash.compare(crypto::SHA256HashString(payload)), 0);
  }
}

}  // namespace test
}  // namespace crypto