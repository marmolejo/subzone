// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/darknet_auth.h"

#include "base/logging.h"
#include "gtest/gtest.h"

namespace net {
namespace test {

const char i1_identity[] = "gAXIdY1ZIY5imCwcISPDmkUCfEf0iT463+k2PkAh8Cw";
const char my_identity[] = "tMh1zG3Vy+c+dfeGqPRn+Df9Ich0K89U6SiAci2hgPk";
const uint16 kPort = 6991;

const int kMinSize = 192;
const int kMaxSize = 291;

// darknet handshake test. Pick a nonce, ECDH keypair, iv and padding length
TEST(DarknetAuth, JFK1) {
  for (int i(0); i < 10; ++i) {
    net::DarknetAuth da(my_identity, i1_identity, "127.0.0.1", kPort);

    // Client sends to the server.
    int bytes_sent { da.SendJFK1() };
    EXPECT_GE(bytes_sent, kMinSize);
    EXPECT_LE(bytes_sent, kMaxSize);
  }
}

}  // namespace test
}  // namespace net
