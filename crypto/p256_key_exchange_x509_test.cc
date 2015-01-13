// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/p256_key_exchange_x509.h"

#include "base/logging.h"
#include "gtest/gtest.h"

using std::string;

namespace crypto {
namespace test {

// SharedKeyX509 tests that the basic key exchange identity holds: that both
// parties end up with the same key, exchanged in the X.509 network format.
TEST(P256KeyExchangeX509, SharedKeyX509) {
  for (int i = 0; i < 5; i++) {
    scoped_ptr<P256KeyExchangeX509> alice(new P256KeyExchangeX509());
    scoped_ptr<P256KeyExchangeX509> bob(new P256KeyExchangeX509());

    ASSERT_TRUE(alice.get() != nullptr);
    ASSERT_TRUE(bob.get() != nullptr);

    const base::StringPiece alice_public_x509(alice->GetX509Public());
    const base::StringPiece bob_public_x509(bob->GetX509Public());

    ASSERT_FALSE(alice_public_x509.empty());
    ASSERT_FALSE(bob_public_x509.empty());
    ASSERT_NE(alice_public_x509, bob_public_x509);

    // Convert X.509 format to public key value
    string alice_public, bob_public;
    ASSERT_TRUE(P256KeyExchangeX509::GetPublicValueFromX509(alice_public_x509,
  	    alice_public));
    ASSERT_TRUE(P256KeyExchangeX509::GetPublicValueFromX509(bob_public_x509,
  	    bob_public));

    ASSERT_EQ(alice_public, alice->public_value());
    ASSERT_EQ(bob_public, bob->public_value());
  }
}

}  // namespace test
}  // namespace crypto
