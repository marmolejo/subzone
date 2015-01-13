// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_P256_KEY_EXCHANGE_X509_H_
#define CRYPTO_P256_KEY_EXCHANGE_X509_H_

#include "net/quic/crypto/p256_key_exchange.h"
#include "base/strings/string_piece.h"
#include "crypto/scoped_openssl_types.h"

namespace crypto {

// An ECDH random key
class P256KeyExchangeX509 : public net::P256KeyExchange {
 public:
 	P256KeyExchangeX509();
 	~P256KeyExchangeX509();

 	// Obtain the public key in X.509 network format
  base::StringPiece GetX509Public() const;

  // GetPublicValueFromX509 parses a X.509 certificate containing the EC public
  // key in |peer_public_x509| and returns the uncompressed public key value
  static bool GetPublicValueFromX509(const base::StringPiece& peer_public_x509,
  	                                 std::string& out_public_value);

 private:
 	enum {
 	  // This includes the algorithm id and parameters
    kP256PublicKeyX509Bytes = 91,
  };

  // The public key stored as a X509 certificate
 	mutable uint8 public_key_x509_[kP256PublicKeyX509Bytes];
 	mutable base::StringPiece public_key_;
};

}  // namespace crypto

#endif  // CRYPTO_P256_KEY_EXCHANGE_X509_H_
