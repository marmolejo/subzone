// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/p256_key_exchange.h"

#include "base/logging.h"
#include "gtest/gtest.h"

namespace crypto {
namespace test {

// Basic test just checks that an EC exchange cannot be built by a wrong private
// key value.
TEST(P256KeyExchange, Basic) {
  P256KeyExchange alice;
  ASSERT_FALSE(alice.Init(base::StringPiece("1234")));
}

// SharedKeyX509 tests that the basic key exchange identity holds: that both
// parties end up with the same key, exchanged in the X.509 network format.
TEST(P256KeyExchange, SharedKeyX509) {
  for (int i = 0; i < 5; i++) {
    scoped_ptr<P256KeyExchange> alice(new P256KeyExchange());
    scoped_ptr<P256KeyExchange> bob(new P256KeyExchange());
    ASSERT_TRUE(alice.get() != nullptr);
    ASSERT_TRUE(bob.get() != nullptr);

    // Initialize alice anb bob's private keys with random values
    alice->Init();
    bob->Init();

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
    alice.Init();

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

// These are a pair of ECDSA keys in DER export format. Note that the private
// key can be derived from the public key. However, we will check this in the
// *Private* test.
const uint8_t public_key[P256KeyExchange::kP256PublicKeyX509Bytes] = {
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  0x04, 0xb3, 0x74, 0x41, 0xcc, 0x7e, 0x36, 0x76, 0xe1, 0x3f, 0x13, 0xd9, 0x8c,
  0x50, 0x8f, 0xb9, 0x53, 0x6e, 0xae, 0x01, 0xe5, 0x2b, 0x20, 0x8f, 0x44, 0x1a,
  0x58, 0xc3, 0x85, 0xf8, 0x58, 0x82, 0x79, 0x0a, 0xf8, 0xae, 0xb2, 0xdb, 0xa7,
  0x30, 0x88, 0x36, 0x10, 0xd2, 0x20, 0x3c, 0xb6, 0xa8, 0xab, 0x2f, 0x76, 0xfe,
  0x50, 0xc3, 0x2c, 0xc4, 0xa8, 0xb8, 0xc3, 0xbb, 0x52, 0xa7, 0x5b, 0x9b, 0x6d
};

const uint8_t private_key[] = {
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, 0x37, 0x53, 0x66, 0x73,
  0xa9, 0x7b, 0x6d, 0x6c, 0x5c, 0xe9, 0x80, 0x61, 0x3b, 0x04, 0xdf, 0xe1, 0x97,
  0x93, 0x5b, 0x9c, 0x85, 0xd6, 0x36, 0xec, 0xad, 0x97, 0xc5, 0xf0, 0x11, 0xda,
  0x77, 0xac
};

// Private key test builds a P256 key exchange from a known private key, then it
// checks that the public key derived from the private matches exactly with the
// one in the reference
TEST(P256KeyExchange, Private) {
  const base::StringPiece private_str(
    reinterpret_cast<const char *>(private_key), sizeof(private_key));

  // Create the exchange from the private key
  P256KeyExchange p256ex;
  p256ex.Init(private_str);

  // Get the public key from the private
  const base::StringPiece public_str(p256ex.GetX509Public());
  const base::StringPiece ref_public(reinterpret_cast<const char *>(public_key),
                                     sizeof(public_key));

  // Public keys must match
  ASSERT_EQ(public_str.compare(ref_public), 0);
}

// The Verify test takes a public key sample value from the Freenet reference
// implementation with a valid signature and checks that our implementation
// can verify the signature appropriatelly.
TEST(P256KeyExchange, Verify) {
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
  const base::StringPiece public_str(reinterpret_cast<const char *>(public_key),
                                     sizeof(public_key));
  const base::StringPiece signature_str(reinterpret_cast<const char *>(sig),
                                        sizeof(sig));

  // It must return true, as this is a valid signature from the public key above
  ASSERT_TRUE(P256KeyExchange::VerifySignature(public_str, signature_str));
}

// The sign test creates multiple signatures from a fixed private EC key. These
// signatures must verify the signature check for the public key. Some results
// have been verified against the same fixed private key in the fred reference
// implementation.
TEST(P256KeyExchange, Sign) {
  for (int i = 0; i < 5; i++) {
    const base::StringPiece private_str(
      reinterpret_cast<const char *>(private_key), sizeof(private_key));

    // Create the exchange from the private key
    P256KeyExchange p256ex;
    p256ex.Init(private_str);

    const base::StringPiece public_str(
      reinterpret_cast<const char *>(public_key), sizeof(public_key));

    // Get the public key signature
    const base::StringPiece p256ex_sig(p256ex.GetSignature());
    ASSERT_FALSE(p256ex_sig.empty());

    // Verify the signature against it's public key.
    ASSERT_TRUE(P256KeyExchange::VerifySignature(public_str, p256ex_sig));
  }
}

}  // namespace test
}  // namespace crypto
