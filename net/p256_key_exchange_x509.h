// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_P256_KEY_EXCHANGE_X509_H_
#define NET_P256_KEY_EXCHANGE_X509_H_

#include "net/quic/crypto/p256_key_exchange.h"
#include "base/strings/string_piece.h"
#include "crypto/scoped_openssl_types.h"

namespace net {

// An ECDH random key
class P256KeyExchangeX509 : public P256KeyExchange {
 public:
 	P256KeyExchangeX509();
 	~P256KeyExchangeX509();

 	// Obtain the public key in X.509 network format
  base::StringPiece GetPublicX509();

 private:
 	enum {
 	  // This includes the algorithm id and parameters
    kP256PublicKeyX509Bytes = 91,
  };

  // The public key stored as a X509 certificate
 	uint8 public_key_x509_[kP256PublicKeyX509Bytes];
 	base::StringPiece public_key_;
};

}  // namespace net

#endif  // NET_P256_KEY_EXCHANGE_X509_H_
