// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_P256_KEY_EXCHANGE_H_
#define CRYPTO_P256_KEY_EXCHANGE_H_

#include <string>

#include "base/strings/string_piece.h"
#include "crypto/scoped_openssl_types.h"

namespace crypto {

// An ECDH random key
class P256KeyExchange {
 public:
  P256KeyExchange();
  ~P256KeyExchange();

  bool CalculateSharedKey(const base::StringPiece& peer_public_value,
                          std::string* shared_key) const;
  base::StringPiece public_value() const;

  // Obtain the public key in X.509 network format
  base::StringPiece GetX509Public() const;

  // GetPublicValueFromX509 parses a X.509 certificate containing the EC public
  // key in |peer_public_x509| and returns the uncompressed public key value
  static bool GetPublicValueFromX509(const base::StringPiece& peer_public_x509,
                                     std::string *out_public_value);

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
    // This includes the algorithm id and parameters
    kP256PublicKeyX509Bytes = 91,
  };

  // The public key stored as a X509 certificate
  mutable uint8 public_key_x509_[kP256PublicKeyX509Bytes];
  mutable base::StringPiece public_key_x509_str_;

  // We use only the OpenSSL implementation
  crypto::ScopedEC_KEY private_key_;

  // The public key stored as an uncompressed P-256 point.
  uint8 public_key_[kUncompressedP256PointBytes];

  DISALLOW_COPY_AND_ASSIGN(P256KeyExchange);
};

}  // namespace crypto

#endif  // CRYPTO_P256_KEY_EXCHANGE_H_
