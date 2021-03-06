// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_P256_KEY_EXCHANGE_H_
#define CRYPTO_P256_KEY_EXCHANGE_H_

#include <string>
#include "base/strings/string_piece.h"
#include "crypto/scoped_openssl_types.h"

namespace crypto {

// An ECDH P-256 random key
class P256KeyExchange {
 public:
  P256KeyExchange();
  ~P256KeyExchange();

  // Init the key exchange. This must be called after the  constructor to build
  // the private key. In the first case it builds the private key from random
  // data. The second creates the exchange from the |private_key| specified.
  // This private key must be a valid EC key in DER network format.
  bool Init();
  bool Init(const base::StringPiece& private_key);

  // CalculateSharedKey builds the shared key between two nodes, given a public
  // key value in |peer_public_value|. |shared_key| is an output parameter that
  // will get the ECDH shared key between two pairs.
  bool CalculateSharedKey(const base::StringPiece& peer_public_value,
                          std::string* shared_key) const;
  base::StringPiece public_value() const;

  // Obtain the public key in X.509 network format
  base::StringPiece GetX509Public() const;

  // Gets the public key X509 ECDSA signature using a SHA-256 digest.
  base::StringPiece GetSignature() const;

  // GetPublicValueFromX509 parses a X.509 certificate containing the EC public
  // key in |peer_public_x509| and returns the uncompressed public key value
  static bool GetPublicValueFromX509(const base::StringPiece& peer_public_x509,
                                     std::string *out_public_value);

  // VerifySignature takes a public EC key and verifies that the |signature|
  // matches with the public key digest SHA-256 signature in |peer_public_x509|,
  // the same public key is used for verification. It returns true if the
  // signature matches with the public key, otherwise returns false.
  static bool VerifySignature(const base::StringPiece& peer_public_x509,
                              const base::StringPiece& signature);

  enum {
    // This includes the algorithm id and parameters
    kP256PublicKeyX509Bytes = 91,
  };

 private:
  enum {
    // A P-256 field element consists of 32 bytes.
    kP256FieldBytes = 32,
    // A P-256 point in uncompressed form consists of 0x04 (to denote
    // that the point is uncompressed) followed by two, 32-byte field
    // elements.
    kUncompressedP256PointBytes = 1 + 2 * kP256FieldBytes,
    // The first byte in an uncompressed P-256 point.
    kUncompressedECPointForm = 0x04,
    // Maximum size of the DER signature
    kSignatureBytes = 72,
  };

  // The public key stored as a X509 certificate
  mutable uint8 public_key_x509_[kP256PublicKeyX509Bytes];
  mutable base::StringPiece public_key_x509_str_;

  // We use only the OpenSSL implementation
  crypto::ScopedEC_KEY private_key_;

  // The public key stored as an uncompressed P-256 point.
  uint8 public_key_[kUncompressedP256PointBytes];

  // Public key signature in DER format.
  mutable uint8 signature_[kSignatureBytes];
  mutable base::StringPiece signature_str_;

  DISALLOW_COPY_AND_ASSIGN(P256KeyExchange);
};

}  // namespace crypto

#endif  // CRYPTO_P256_KEY_EXCHANGE_H_
