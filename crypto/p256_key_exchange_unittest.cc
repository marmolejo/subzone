// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/p256_key_exchange.h"

#include "base/logging.h"
#include "gtest/gtest.h"

namespace crypto {
namespace test {

// SharedKeyX509 tests that the basic key exchange identity holds: that both
// parties end up with the same key, exchanged in the X.509 network format.
TEST(P256KeyExchange, SharedKeyX509) {
  for (int i = 0; i < 5; i++) {
    scoped_ptr<P256KeyExchange> alice(new P256KeyExchange());
    scoped_ptr<P256KeyExchange> bob(new P256KeyExchange());
    ASSERT_TRUE(alice.get() != nullptr);
    ASSERT_TRUE(bob.get() != nullptr);

    const base::StringPiece alice_public_x509(alice->GetX509Public());
    const base::StringPiece bob_public_x509(bob->GetX509Public());

    ASSERT_FALSE(alice_public_x509.empty());
    ASSERT_FALSE(bob_public_x509.empty());
    ASSERT_NE(alice_public_x509, bob_public_x509);

    // Convert X.509 format to public key value
    std::string alice_public, bob_public;
    ASSERT_TRUE(P256KeyExchange::GetPublicValueFromX509(alice_public_x509,
        &alice_public));
    ASSERT_TRUE(P256KeyExchange::GetPublicValueFromX509(bob_public_x509,
        &bob_public));

    // These public keys must match
    ASSERT_EQ(alice_public, alice->public_value());
    ASSERT_EQ(bob_public, bob->public_value());
  }
}

// The SignAndVerify test generates a key exchange (public/private key pair) and
// takes the public key value and signs it. Finally it verifies that the
// signature matches with the public key signature. We repeat this test 5 times.
TEST(P256KeyExchange, SignAndVerify) {
  for (int i = 0; i < 5; i++) {
    P256KeyExchange alice;
    const base::StringPiece alice_sig(alice.GetSignature());
    ASSERT_FALSE(alice_sig.empty());

    // Take the public key in DER format. This is the string that is going to be
    // passed through the SHA256 and then signed.
    const base::StringPiece public_x509(alice.GetX509Public());
    ASSERT_FALSE(public_x509.empty());

    // Verify the signature against it's public key.
    ASSERT_TRUE(P256KeyExchange::VerifySignature(public_x509, alice_sig));
  }
}

// The Verify test takes a public key sample value from the Freenet reference
// implementation with a valid signature and checks that our implementation
// can verify the signature appropriatelly.
TEST(P256KeyExchange, Verify) {
  // Public key in X509 network format.
  const uint8_t pubx509[P256KeyExchange::kP256PublicKeyX509Bytes] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xb3, 0x74, 0x41, 0xcc, 0x7e, 0x36, 0x76, 0xe1, 0x3f,
    0x13, 0xd9, 0x8c, 0x50, 0x8f, 0xb9, 0x53, 0x6e, 0xae, 0x01, 0xe5, 0x2b,
    0x20, 0x8f, 0x44, 0x1a, 0x58, 0xc3, 0x85, 0xf8, 0x58, 0x82, 0x79, 0x0a,
    0xf8, 0xae, 0xb2, 0xdb, 0xa7, 0x30, 0x88, 0x36, 0x10, 0xd2, 0x20, 0x3c,
    0xb6, 0xa8, 0xab, 0x2f, 0x76, 0xfe, 0x50, 0xc3, 0x2c, 0xc4, 0xa8, 0xb8,
    0xc3, 0xbb, 0x52, 0xa7, 0x5b, 0x9b, 0x6d
  };

  // Signature in DER export format.
  const uint8_t sig[] = {
    0x30, 0x45, 0x02, 0x20, 0x6c, 0x0c, 0x5b, 0x93, 0x30, 0xb9, 0x59, 0xf8,
    0xcb, 0x23, 0x38, 0xec, 0x13, 0xc3, 0x51, 0xb9, 0x72, 0x61, 0x14, 0xa9,
    0xc2, 0xf5, 0x59, 0x97, 0x23, 0x09, 0x00, 0x52, 0x57, 0xab, 0x49, 0x22,
    0x02, 0x21, 0x00, 0x95, 0xe3, 0xd4, 0xa1, 0xcd, 0x7e, 0xe3, 0x84, 0x48,
    0x5f, 0x56, 0x23, 0xd3, 0x2b, 0x0b, 0x15, 0x43, 0xce, 0x3a, 0x35, 0x68,
    0xc6, 0xaa, 0x2a, 0xf2, 0x80, 0x0a, 0x0d, 0x22, 0x38, 0xb2, 0x38
  };

  // Convert the byte arrays to strings to be able to call VerifySignature()
  const base::StringPiece pubx509_str(reinterpret_cast<const char *>(pubx509),
                                      sizeof(pubx509));
  const base::StringPiece sig_str(reinterpret_cast<const char *>(sig),
                                  sizeof(sig));

  // It must return true, as this is a valid signature from the public key above
  ASSERT_TRUE(P256KeyExchange::VerifySignature(pubx509_str, sig_str));
}

}  // namespace test
}  // namespace crypto

