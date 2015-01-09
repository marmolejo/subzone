// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/p256_key_exchange_x509.h"
#include "net/quic/crypto/p256_key_exchange.h"

#include <openssl/x509.h>

namespace net {

P256KeyExchangeX509::P256KeyExchangeX509() 
  : P256KeyExchange (P256KeyExchange::New(
  	  P256KeyExchange::NewPrivateKey())) {
}

P256KeyExchangeX509::~P256KeyExchangeX509() {
}

base::StringPiece P256KeyExchangeX509::GetPublicX509() {
	if (!public_key_.empty()) return public_key_;
	
  // We get the public in X.509 format from the private key
  crypto::ScopedEVP_PKEY pkey(EVP_PKEY_new());
  EVP_PKEY_set1_EC_KEY(pkey.get(), private_key_.get());

  uint8 *public_key = public_key_x509_;
  i2d_PUBKEY(pkey.get(), &public_key);
  public_key_.set(reinterpret_cast<char *>(public_key_x509_), 
  	  kP256PublicKeyX509Bytes);

  return public_key_;
}

}  // namespace net
